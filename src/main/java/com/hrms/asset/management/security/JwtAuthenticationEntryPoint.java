package com.hrms.asset.management.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request,
                        HttpServletResponse response,
                        AuthenticationException authException) throws IOException, ServletException {
        
        log.error("=== Authentication Failed ===");
        log.error("Path: {}", request.getRequestURI());
        log.error("Method: {}", request.getMethod());
        log.error("Exception: {}", authException.getMessage());
        
        // Log the cause chain to understand the error
        Throwable cause = authException.getCause();
        if (cause != null) {
            log.error("Root cause: {} - {}", cause.getClass().getSimpleName(), cause.getMessage());
        }

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", Instant.now().toString());
        errorDetails.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        errorDetails.put("error", "Unauthorized");
        errorDetails.put("path", request.getRequestURI());
        
        // Determine specific error type
        String message = "Authentication failed";
        String errorCode = "UNAUTHORIZED";
        
        // Check if it's a JWT-related error
        if (authException.getCause() instanceof JwtException) {
            JwtException jwtException = (JwtException) authException.getCause();
            String jwtMessage = jwtException.getMessage();
            
            log.error("JWT Exception detected: {}", jwtMessage);
            
            // Parse the JWT error message to determine specific error type
            if (jwtMessage.contains("expired")) {
                message = "Token has expired. Please login again.";
                errorCode = "TOKEN_EXPIRED";
                log.warn("TOKEN_EXPIRED: {}", jwtMessage);
                
            } else if (jwtMessage.contains("invalid")) {
                message = "Invalid token provided";
                errorCode = "INVALID_TOKEN";
                log.warn("INVALID_TOKEN: {}", jwtMessage);
                
            } else if (jwtMessage.contains("tenant") || jwtMessage.contains("issuer")) {
                message = "Token does not belong to the specified tenant";
                errorCode = "INVALID_TENANT";
                log.warn("INVALID_TENANT: {}", jwtMessage);
                
            } else if (jwtMessage.contains("signature")) {
                message = "Token signature verification failed";
                errorCode = "INVALID_SIGNATURE";
                log.warn("INVALID_SIGNATURE: {}", jwtMessage);
                
            } else {
                message = "Token validation failed";
                errorCode = "TOKEN_VALIDATION_FAILED";
                log.error("UNKNOWN_JWT_ERROR: {}", jwtMessage);
            }
            
        } else if (authException.getMessage() != null) {
            // Handle other authentication errors
            String authMessage = authException.getMessage().toLowerCase();
            
            if (authMessage.contains("token")) {
                message = "Token authentication failed";
                errorCode = "TOKEN_AUTH_FAILED";
            } else if (authMessage.contains("missing")) {
                message = "Authentication token is missing";
                errorCode = "TOKEN_MISSING";
            } else {
                message = authException.getMessage();
                errorCode = "AUTHENTICATION_FAILED";
            }
        }
        
        errorDetails.put("message", message);
        errorDetails.put("errorCode", errorCode);
        
        // Add tenant info if available
        String tenantHeader = request.getHeader("X-Tenant-ID");
        if (tenantHeader != null) {
            errorDetails.put("tenant", tenantHeader);
        }
        
        log.error("Returning error response: {} - {}", errorCode, message);
        log.error("=== End Authentication Error ===");
        
        objectMapper.writeValue(response.getOutputStream(), errorDetails);
    }
}