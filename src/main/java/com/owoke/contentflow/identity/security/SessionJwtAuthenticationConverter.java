package com.owoke.contentflow.identity.security;

import java.time.Clock;
import java.util.List;
import java.util.UUID;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.owoke.contentflow.identity.entity.UserStatus;
import com.owoke.contentflow.identity.repository.AuthSessionRepository;
import com.owoke.contentflow.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class SessionJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final AuthSessionRepository sessions;
    private final UserRepository users;
    private final Clock clock;

    @Override
    @Transactional(readOnly = true)
    public AbstractAuthenticationToken convert(Jwt jwt) {
        UUID userId;
        UUID sessionId;
        try {
            userId = UUID.fromString(jwt.getSubject());
            sessionId = UUID.fromString(jwt.getClaimAsString("sid"));
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw rejected("ACCESS_TOKEN_INVALID");
        }
        var session = sessions.findById(sessionId).orElseThrow(() -> rejected("SESSION_REVOKED"));
        if (!session.getUserId().equals(userId) || session.getRevokedAt() != null
                || !session.getExpiresAt().isAfter(clock.instant())) { throw rejected("SESSION_REVOKED"); }
        var user = users.findById(userId).orElseThrow(() -> rejected("SESSION_REVOKED"));
        if (user.getStatus() != UserStatus.ACTIVE) { throw rejected("SESSION_REVOKED"); }
        return new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private OAuth2AuthenticationException rejected(String code) {
        return new OAuth2AuthenticationException(new OAuth2Error(code));
    }
}
