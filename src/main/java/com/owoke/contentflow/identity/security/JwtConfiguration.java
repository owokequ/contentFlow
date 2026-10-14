package com.owoke.contentflow.identity.security;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.List;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

@Configuration
@EnableConfigurationProperties(TokenProperties.class)
public class JwtConfiguration {
    @Bean
    RSAKey signingKey(TokenProperties properties) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                new X509EncodedKeySpec(pem(properties.publicKey(), "PUBLIC KEY")));
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(
                new PKCS8EncodedKeySpec(pem(properties.privateKey(), "PRIVATE KEY")));
        if (publicKey.getModulus().bitLength() < 2048
                || !publicKey.getModulus().equals(privateKey.getModulus())) {
            throw new IllegalArgumentException("JWT requires a matching RSA key pair of at least 2048 bits");
        }
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID("contentflow-rsa").build();
    }

    @Bean
    JwtEncoder jwtEncoder(RSAKey key) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }

    @Bean
    JwtDecoder jwtDecoder(RSAKey key, TokenProperties properties, Clock clock) throws Exception {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256).build();
        OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience() != null
                && jwt.getAudience().contains(properties.audience())
                ? OAuth2TokenValidatorResult.success() : invalid("ACCESS_TOKEN_INVALID");
        OAuth2TokenValidator<Jwt> requiredClaims = jwt -> {
            if (jwt.getExpiresAt() == null || jwt.getIssuedAt() == null || jwt.getSubject() == null
                    || !(jwt.getClaims().get("sid") instanceof String) || jwt.getId() == null) {
                return invalid("ACCESS_TOKEN_INVALID");
            }
            if (!jwt.getExpiresAt().isAfter(clock.instant())) { return invalid("ACCESS_TOKEN_EXPIRED"); }
            if (jwt.getIssuedAt().isAfter(clock.instant().plusSeconds(30))) {
                return invalid("ACCESS_TOKEN_INVALID");
            }
            return OAuth2TokenValidatorResult.success();
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(
                JwtValidators.createDefaultWithIssuer(properties.issuer()), audience, requiredClaims)));
        return decoder;
    }

    private static OAuth2TokenValidatorResult invalid(String code) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(code, "Invalid access token", null));
    }

    private static byte[] pem(Resource resource, String type) throws Exception {
        try (var input = resource.getInputStream()) {
            String value = new String(input.readAllBytes(), StandardCharsets.US_ASCII)
                    .replace("-----BEGIN " + type + "-----", "")
                    .replace("-----END " + type + "-----", "").replaceAll("\\s", "");
            return Base64.getDecoder().decode(value);
        }
    }
}
