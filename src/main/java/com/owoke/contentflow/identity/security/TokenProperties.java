package com.owoke.contentflow.identity.security;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Validated
@ConfigurationProperties("identity.tokens")
public record TokenProperties(
        @NotBlank String issuer, @NotBlank String audience,
        @NotNull Resource privateKey, @NotNull Resource publicKey,
        @NotNull Duration accessTtl, @NotNull Duration sessionTtl,
        boolean cookieSecure, List<String> allowedOrigins) {
    public TokenProperties {
        allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
        if (accessTtl != null && (accessTtl.isNegative() || accessTtl.isZero())
                || sessionTtl != null && (sessionTtl.isNegative() || sessionTtl.isZero())) {
            throw new IllegalArgumentException("Token lifetimes must be positive");
        }
        if (allowedOrigins.contains("*")) {
            throw new IllegalArgumentException("Use explicit frontend origins");
        }
    }
}
