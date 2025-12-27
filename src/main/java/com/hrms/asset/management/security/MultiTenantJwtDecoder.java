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
        try {
            // Get tenant from context (already set by TenantFilter from X-Tenant-ID header)
            String realmName = TenantContext.getCurrentTenant();

            if (realmName == null) {
                throw new JwtException("Tenant context not set. X-Tenant-ID header missing?");
            }

            log.debug("Validating token for tenant: {}", realmName);


            // Parse JWT to extract issuer (for additional verification)
            JWT jwt = JWTParser.parse(token);
            String tokenIssuer = jwt.getJWTClaimsSet().getIssuer();
            String expectedIssuer = keycloakBaseUrl + "/realms/" + realmName;

            // Verify token issuer matches tenant's realm
            if (!tokenIssuer.equals(expectedIssuer)) {
                log.error("Token issuer mismatch! Expected: {}, Got: {}", expectedIssuer, tokenIssuer);
                throw new JwtException("Token does not belong to tenant: " + realmName);
            }

            log.debug("Token issuer verified: {}", tokenIssuer);

            // Get or create decoder for this realm
            JwtDecoder decoder = jwtDecoders.computeIfAbsent(realmName,
                    this::createJwtDecoder);

            // Decode and validate token
            Jwt decodedJwt = decoder.decode(token);

            log.info("Token validated successfully for t(realm: {})", realmName);

            return decodedJwt;

        } catch (JwtException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to decode JWT", e);
            throw new JwtException("Failed to decode JWT: " + e.getMessage());
        }
    }

    private JwtDecoder createJwtDecoder(String realmName) {
        String jwkSetUri = keycloakBaseUrl + "/realms/" + realmName +
                "/protocol/openid-connect/certs";
        String issuerUri = keycloakBaseUrl + "/realms/" + realmName;

        log.info("Creating JWT decoder for realm: {}", realmName);

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        // Add issuer validation
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        jwtDecoder.setJwtValidator(withIssuer);

        return jwtDecoder;
    }
}