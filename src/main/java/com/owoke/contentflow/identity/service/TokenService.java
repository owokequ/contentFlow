package com.owoke.contentflow.identity.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.owoke.contentflow.identity.dto.request.LoginRequest;
import com.owoke.contentflow.identity.entity.*;
import com.owoke.contentflow.identity.exception.InvalidCredentialsException;
import com.owoke.contentflow.identity.exception.RefreshTokenRejectedException;
import com.owoke.contentflow.identity.repository.*;
import com.owoke.contentflow.identity.security.IdentityUserDetails;
import com.owoke.contentflow.identity.security.TokenProperties;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final AuthenticationManager authentication;
    private final UserRepository users;
    private final AuthSessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final JwtEncoder encoder;
    private final TokenProperties properties;
    private final Clock clock;
    private final PlatformTransactionManager transactionManager;
    private final SecureRandom random = new SecureRandom();

    public IssuedTokens login(LoginRequest request, ClientType clientType) {
        IdentityUserDetails principal;
        try {
            principal = (IdentityUserDetails) authentication.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(request.email(), request.password()))
                    .getPrincipal();
        } catch (AuthenticationException ex) { throw new InvalidCredentialsException(); }
        // Authenticate before starting the write transaction: no nested transaction or stale user cache.
        return new TransactionTemplate(transactionManager).execute(status -> openSession(principal, clientType));
    }

    private IssuedTokens openSession(IdentityUserDetails principal, ClientType clientType) {
        // Lock user before session everywhere, including password changes and logout.
        User user = users.findForUpdate(principal.userId()).orElseThrow(InvalidCredentialsException::new);
        if (user.getStatus() != UserStatus.ACTIVE || !user.getPasswordHash().equals(principal.getPassword())
                || !user.getEmail().equals(principal.getUsername())) {
            throw new InvalidCredentialsException();
        }
        AuthSession session = new AuthSession();
        session.setUserId(user.getId());
        session.setClientType(clientType);
        session.setExpiresAt(clock.instant().plus(properties.sessionTtl()));
        sessions.saveAndFlush(session);
        return issue(session);
    }

    // A replay must commit the session revocation before returning 401.
    @Transactional(noRollbackFor = RefreshTokenRejectedException.class)
    public IssuedTokens refresh(String rawToken, ClientType clientType) {
        String hash = tokenHash(rawToken);
        AuthSession session = lockSession(hash);
        if (session == null || session.getClientType() != clientType) { throw new RefreshTokenRejectedException(); }
        RefreshToken token = refreshTokens.findByTokenHash(hash).orElseThrow(RefreshTokenRejectedException::new);
        var now = clock.instant();
        if (session.getRevokedAt() != null || !session.getExpiresAt().isAfter(now)
                || !token.getExpiresAt().isAfter(now)) { throw new RefreshTokenRejectedException(); }
        if (token.getUsedAt() != null) {
            session.setRevokedAt(now);
            throw new RefreshTokenRejectedException();
        }
        token.setUsedAt(now);
        return issue(session);
    }

    @Transactional
    public void logout(String rawToken, ClientType clientType) {
        if (!validShape(rawToken)) { return; }
        AuthSession session = lockSession(tokenHash(rawToken));
        if (session != null && session.getClientType() == clientType && session.getRevokedAt() == null) {
            session.setRevokedAt(clock.instant());
        }
    }

    private AuthSession lockSession(String hash) {
        var sessionId = refreshTokens.findSessionIdByHash(hash).orElse(null);
        if (sessionId == null) { return null; }
        var userId = sessions.findUserIdById(sessionId).orElse(null);
        if (userId == null) { return null; }
        var user = users.findForUpdate(userId).orElse(null);
        if (user == null || user.getStatus() != UserStatus.ACTIVE) { return null; }
        return sessions.findForUpdate(sessionId).orElse(null);
    }

    private IssuedTokens issue(AuthSession session) {
        var now = clock.instant();
        var expiresAt = now.plus(properties.accessTtl());
        if (expiresAt.isAfter(session.getExpiresAt())) { expiresAt = session.getExpiresAt(); }
        var claims = JwtClaimsSet.builder().issuer(properties.issuer()).subject(session.getUserId().toString())
                .audience(java.util.List.of(properties.audience())).issuedAt(now).expiresAt(expiresAt)
                .id(UUID.randomUUID().toString()).claim("sid", session.getId().toString()).build();
        String access = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).keyId("contentflow-rsa").build(), claims)).getTokenValue();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        RefreshToken token = new RefreshToken();
        token.setSessionId(session.getId());
        token.setTokenHash(tokenHash(raw));
        token.setCreatedAt(now);
        token.setExpiresAt(session.getExpiresAt());
        refreshTokens.saveAndFlush(token);
        return new IssuedTokens(access, raw, Math.max(0, java.time.Duration.between(now, expiresAt).toSeconds()),
                session.getExpiresAt());
    }

    private boolean validShape(String value) { return value != null && value.matches("[A-Za-z0-9_-]{43}"); }

    private String tokenHash(String value) {
        if (!validShape(value)) { throw new RefreshTokenRejectedException(); }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
}
