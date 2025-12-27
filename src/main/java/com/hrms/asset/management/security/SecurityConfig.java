package com.hrms.asset.management.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.annotation.PostConstruct;
import java.util.Collection;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final MultiTenantJwtDecoder multiTenantJwtDecoder;

    @PostConstruct
    public void init() {
        log.info("=== Initializing Security Configuration ===");
        log.info("Multi-tenant JWT authentication enabled");
        log.info("Method-level security (@PreAuthorize) enabled");
        log.info("Security features:");
        log.info("   ✓ JWT token validation");
        log.info("   ✓ Multi-tenant support");
        log.info("   ✓ Role-based access control");
        log.info("   ✓ Public endpoint bypass");
        log.info("=========================================");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("🔒 Configuring Security Filter Chain...");

        // Configure CSRF
        log.debug("Disabling CSRF protection (stateless REST API with JWT tokens)");
        http.csrf(csrf -> csrf.disable());

        // Configure authorization rules
        log.info("Setting up authorization rules:");
        log.info("   Public endpoints (no authentication required):");
        log.info("      - /actuator/health");
        log.info("      - /api/public/**");
        log.info("   Protected endpoints (authentication required):");
        log.info("      - All other endpoints");

        http.authorizeHttpRequests(authz -> {
            log.debug("Configuring request matchers...");
            authz
                    .requestMatchers("/actuator/health", "/api/public/**").permitAll()
                    .anyRequest().authenticated();
            log.debug("Authorization rules configured successfully");
        });

        // Configure OAuth2 Resource Server with JWT
        log.info("Configuring OAuth2 Resource Server with JWT authentication");
        log.debug("Using MultiTenantJwtDecoder for token validation");

        http.oauth2ResourceServer(oauth2 -> {
            log.debug("Setting up JWT decoder and authentication converter...");
            oauth2.jwt(jwt -> {
                jwt.decoder(multiTenantJwtDecoder);
                jwt.jwtAuthenticationConverter(jwtAuthenticationConverter());
                log.debug("JWT configuration completed");
            });
        });

        SecurityFilterChain chain = http.build();
        log.info("✓ Security Filter Chain built successfully");
        log.debug("Filter chain contains {} filters", chain.getFilters().size());

        return chain;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        log.info("🔧 Creating JWT Authentication Converter...");

        // Create authorities converter
        log.debug("Configuring JWT Granted Authorities Converter");
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter =
                new JwtGrantedAuthoritiesConverter();

        log.info("Role extraction configuration:");
        log.info("   Claim name: realm_access.roles");
        log.info("   Authority prefix: ROLE_");
        log.info("   Example: 'USER' in JWT → 'ROLE_USER' in Spring Security");

        grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access.roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        // Create main converter with custom authorities converter
        log.debug("Creating main JWT authentication converter");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        // Add logging wrapper to see what roles are extracted
        JwtAuthenticationConverter loggingConverter = new JwtAuthenticationConverter() {
            @Override
            public org.springframework.security.core.Authentication convert(Jwt jwt) {
                String username = jwt.getClaimAsString("preferred_username");
                String subject = jwt.getSubject();

                log.debug("Converting JWT to Authentication object");
                log.debug("   Subject: {}", subject);
                log.debug("   Username: {}", username);

                // Get the converted authentication
                org.springframework.security.core.Authentication authentication =
                        converter.convert(jwt);

                if (authentication != null) {
                    Collection<? extends GrantedAuthority> authorities =
                            authentication.getAuthorities();

                    log.info("✓ Authentication created for user: [{}]", username);
                    log.info("   Subject ID: {}", subject);
                    log.info("   Granted authorities: {}", authorities);
                    log.debug("   Total authorities: {}", authorities.size());

                    // Log each role individually for clarity
                    if (log.isDebugEnabled()) {
                        authorities.forEach(authority ->
                                log.debug("      - {}", authority.getAuthority())
                        );
                    }
                } else {
                    log.warn("⚠ Authentication object is null for user: {}", username);
                }

                return authentication;
            }
        };

        // Copy the configuration to the logging converter
        loggingConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        log.info("✓ JWT Authentication Converter created successfully");

        return loggingConverter;
    }

    /**
     * Custom exception handler for authentication failures
     * This helps log authentication errors for debugging
     */
    @Bean
    public org.springframework.boot.web.servlet.FilterRegistrationBean<SecurityLoggingFilter>
    securityLoggingFilter() {

        log.debug("Registering Security Logging Filter");

        org.springframework.boot.web.servlet.FilterRegistrationBean<SecurityLoggingFilter>
                registrationBean = new org.springframework.boot.web.servlet.FilterRegistrationBean<>();

        registrationBean.setFilter(new SecurityLoggingFilter());
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(2); // After tenant filter

        log.debug("Security Logging Filter registered");

        return registrationBean;
    }

    /**
     * Filter to log security events
     */
    @Slf4j
    public static class SecurityLoggingFilter implements jakarta.servlet.Filter {

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request,
                             jakarta.servlet.ServletResponse response,
                             jakarta.servlet.FilterChain chain)
                throws java.io.IOException, jakarta.servlet.ServletException {

            jakarta.servlet.http.HttpServletRequest httpRequest =
                    (jakarta.servlet.http.HttpServletRequest) request;
            jakarta.servlet.http.HttpServletResponse httpResponse =
                    (jakarta.servlet.http.HttpServletResponse) response;

            String requestUri = httpRequest.getRequestURI();
            String method = httpRequest.getMethod();

            // Check if this is a public endpoint
            boolean isPublic = requestUri.startsWith("/actuator/health") ||
                    requestUri.startsWith("/api/public/");

            if (isPublic) {
                log.debug("🌐 Public endpoint accessed: {} {}", method, requestUri);
            } else {
                log.debug("🔒 Protected endpoint accessed: {} {}", method, requestUri);
            }

            long startTime = System.currentTimeMillis();

            try {
                chain.doFilter(request, response);

                long duration = System.currentTimeMillis() - startTime;
                int status = httpResponse.getStatus();

                if (status == 200 || status == 201) {
                    log.debug("✓ Request completed: {} {} - Status: {} ({}ms)",
                            method, requestUri, status, duration);
                } else if (status == 401) {
                    log.warn("❌ Authentication failed: {} {} - Status: 401 Unauthorized ({}ms)",
                            method, requestUri, duration);
                    log.warn("Possible reasons:");
                    log.warn("   1. No Authorization header provided");
                    log.warn("   2. Invalid or expired JWT token");
                    log.warn("   3. Token from wrong realm/tenant");
                } else if (status == 403) {
                    log.warn("❌ Authorization failed: {} {} - Status: 403 Forbidden ({}ms)",
                            method, requestUri, duration);
                    log.warn("User is authenticated but lacks required role/permission");
                } else {
                    log.info("Request completed: {} {} - Status: {} ({}ms)",
                            method, requestUri, status, duration);
                }

            } catch (Exception e) {
                long duration = System.currentTimeMillis() - startTime;
                log.error("❌ Security error during request: {} {} ({}ms)",
                        method, requestUri, duration, e);
                throw e;
            }
        }
    }
}