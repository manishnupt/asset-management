package com.hrms.asset.management.security;

import com.hrms.asset.management.utility.TenantContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
@Slf4j
public class MultiTenantJwtDecoder implements JwtDecoder {

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

    @Override
    public Jwt decode(String token) throws JwtException {
        long startTime = System.currentTimeMillis();
        String realmName = null;

        try {
            log.debug("=== Starting JWT token validation ===");

            // Get tenant from context (already set by TenantFilter from X-Tenant-ID header)
            realmName = TenantContext.getCurrentTenant();

            log.info("Retrieved tenant from context: [{}]", realmName);

            if (realmName == null || realmName.trim().isEmpty()) {
                log.error("Tenant context is null or empty - X-Tenant-ID header was not set by TenantFilter");
                throw new JwtException("Tenant context not set. X-Tenant-ID header missing?");
            }

            log.debug("Validating JWT token for realm: [{}]", realmName);

            // Log token preview (first 20 chars for security)
            String tokenPreview = token.length() > 20 ? token.substring(0, 20) + "..." : token;
            log.debug("Token preview: {}", tokenPreview);

            // Parse JWT to extract issuer (for additional verification)
            log.debug("Parsing JWT to extract claims...");
            JWT jwt = JWTParser.parse(token);

            String tokenIssuer = jwt.getJWTClaimsSet().getIssuer();
            String tokenSubject = jwt.getJWTClaimsSet().getSubject();
            String expectedIssuer = keycloakBaseUrl + "/realms/" + realmName;

            log.info("Token details - Subject: [{}], Issuer: [{}]", tokenSubject, tokenIssuer);
            log.debug("Expected issuer: [{}]", expectedIssuer);

            // Verify token issuer matches tenant's realm
            if (!tokenIssuer.equals(expectedIssuer)) {
                log.error("❌ Token issuer mismatch!");
                log.error("   Expected issuer: [{}]", expectedIssuer);
                log.error("   Actual issuer:   [{}]", tokenIssuer);
                log.error("   Tenant/Realm:    [{}]", realmName);
                log.error("This usually means:");
                log.error("   1. Token is from a different realm/tenant");
                log.error("   2. X-Tenant-ID header doesn't match the token's realm");
                log.error("   3. Token was obtained from wrong Keycloak realm");
                throw new JwtException("Token does not belong to tenant: " + realmName +
                        ". Token issuer: " + tokenIssuer + ", Expected: " + expectedIssuer);
            }

            log.debug("✓ Token issuer verification passed");

            // Check if decoder already exists for this realm
            boolean decoderExists = jwtDecoders.containsKey(realmName);
            if (decoderExists) {
                log.debug("Using cached JWT decoder for realm: [{}]", realmName);
            } else {
                log.info("No cached decoder found for realm: [{}], creating new decoder...", realmName);
            }

            // Get or create decoder for this realm
            JwtDecoder decoder = jwtDecoders.computeIfAbsent(realmName, this::createJwtDecoder);

            log.debug("Validating JWT signature and claims...");

            // Decode and validate token
            Jwt decodedJwt = decoder.decode(token);

            long duration = System.currentTimeMillis() - startTime;

            log.info("✓ Token validated successfully for realm: [{}] in {}ms", realmName, duration);
            log.debug("Decoded token claims: sub={}, preferred_username={}, exp={}",
                    decodedJwt.getSubject(),
                    decodedJwt.getClaimAsString("preferred_username"),
                    decodedJwt.getExpiresAt());
            log.debug("Token contains {} claims", decodedJwt.getClaims().size());

            return decodedJwt;

        } catch (JwtException e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("❌ JWT validation failed for realm: [{}] after {}ms - {}",
                    realmName, duration, e.getMessage());
            throw e;
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("❌ Unexpected error during JWT decoding for realm: [{}] after {}ms",
                    realmName, duration, e);
            log.error("Error type: {}", e.getClass().getName());
            log.error("Error message: {}", e.getMessage());

            // Log stack trace only in debug mode
            if (log.isDebugEnabled()) {
                log.debug("Full stack trace:", e);
            }

            throw new JwtException("Failed to decode JWT: " + e.getMessage(), e);
        } finally {
            log.debug("=== JWT validation completed ===");
        }
    }

    private JwtDecoder createJwtDecoder(String realmName) {
        log.info("🔧 Creating new JWT decoder for realm: [{}]", realmName);

        String jwkSetUri = keycloakBaseUrl + "/realms/" + realmName +
                "/protocol/openid-connect/certs";
        String issuerUri = keycloakBaseUrl + "/realms/" + realmName;

        log.info("Decoder configuration:");
        log.info("   Realm:       [{}]", realmName);
        log.info("   JWK Set URI: [{}]", jwkSetUri);
        log.info("   Issuer URI:  [{}]", issuerUri);
        log.info("   Keycloak:    [{}]", keycloakBaseUrl);

        try {
            log.debug("Building NimbusJwtDecoder with JWK Set URI...");
            NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

            log.debug("Adding issuer validation to decoder...");
            OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
            jwtDecoder.setJwtValidator(withIssuer);

            log.info("✓ JWT decoder created successfully for realm: [{}]", realmName);
            log.info("Decoder cached for reuse - subsequent requests will be faster");

            // Store metadata about when decoder was created
            int currentCacheSize = jwtDecoders.size() + 1; // +1 because we're about to add this one
            log.debug("JWT decoder cache size: {}", currentCacheSize);

            return jwtDecoder;

        } catch (Exception e) {
            log.error("❌ Failed to create JWT decoder for realm: [{}]", realmName, e);
            log.error("Error details: {}", e.getMessage());
            log.error("Please verify:");
            log.error("   1. Keycloak is accessible at: {}", keycloakBaseUrl);
            log.error("   2. Realm '{}' exists in Keycloak", realmName);
            log.error("   3. Network connectivity to Keycloak");
            log.error("   4. JWK endpoint is accessible: {}", jwkSetUri);
            throw new IllegalStateException("Cannot create JWT decoder for realm: " + realmName, e);
        }
    }

    /**
     * Utility method to get cache statistics (useful for monitoring)
     */
    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new ConcurrentHashMap<>();
        stats.put("cachedRealms", jwtDecoders.size());
        stats.put("realmNames", jwtDecoders.keySet());

        log.debug("JWT Decoder Cache Stats: {}", stats);
        return stats;
    }

    /**
     * Clear the decoder cache (useful for testing or when realms are updated)
     */
    public void clearCache() {
        int size = jwtDecoders.size();
        jwtDecoders.clear();
        log.warn("JWT decoder cache cleared - {} decoders removed", size);
    }

    /**
     * Remove specific realm decoder from cache
     */
    public void evictRealm(String realmName) {
        JwtDecoder removed = jwtDecoders.remove(realmName);
        if (removed != null) {
            log.info("Evicted JWT decoder for realm: [{}] from cache", realmName);
        } else {
            log.debug("No decoder found in cache for realm: [{}]", realmName);
        }
    }
}