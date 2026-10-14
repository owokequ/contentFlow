package com.owoke.contentflow.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import com.owoke.contentflow.PostgresIntegrationTest;
import com.owoke.contentflow.identity.dto.request.*;
import com.owoke.contentflow.identity.entity.*;
import com.owoke.contentflow.identity.repository.*;
import com.owoke.contentflow.identity.security.TokenProperties;
import jakarta.servlet.http.Cookie;
import tools.jackson.databind.json.JsonMapper;

class TokenApiIntegrationTests extends PostgresIntegrationTest {
    private static final String PASSWORD = "test-password-12345";
    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired UserRepository users;
    @Autowired AuthSessionRepository sessions;
    @Autowired RefreshTokenRepository refreshTokens;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtDecoder decoder;
    @Autowired JwtEncoder encoder;
    @Autowired TokenProperties properties;
    @Autowired org.springframework.jdbc.core.JdbcTemplate jdbc;

    @Test
    void apiLoginCreatesSessionAndStoresOnlyRefreshHash() throws Exception {
        User user = user();
        Pair pair = login(user);
        var jwt = decoder.decode(pair.access());
        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getAudience()).containsExactly(properties.audience());
        assertThat(jwt.getExpiresAt().getEpochSecond() - jwt.getIssuedAt().getEpochSecond()).isEqualTo(900);
        var session = sessions.findById(UUID.fromString(jwt.getClaimAsString("sid"))).orElseThrow();
        assertThat(session.getClientType()).isEqualTo(ClientType.API);
        assertThat(session.getExpiresAt()).isAfter(Instant.now().plusSeconds(29 * 86400));
        var token = refreshTokens.findAll().stream().filter(t -> t.getSessionId().equals(session.getId())).findFirst().orElseThrow();
        assertThat(token.getTokenHash()).hasSize(64).isNotEqualTo(pair.refresh());
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + pair.access()))
                .andExpect(status().isOk()).andExpect(jsonPath("id").value(user.getId().toString()));
    }

    @Test
    void unknownWrongPasswordAndDisabledUserHaveSameLoginError() throws Exception {
        User user = user();
        invalidLogin(UUID.randomUUID() + "@example.com", PASSWORD);
        invalidLogin(user.getEmail(), "wrong-password");
        user.setStatus(UserStatus.DISABLED);
        users.saveAndFlush(user);
        invalidLogin(user.getEmail(), PASSWORD);
    }

    @Test
    void refreshRotatesAndReplayCommitsRevocation() throws Exception {
        Pair original = login(user());
        Pair rotated = refresh(original.refresh());
        assertThat(rotated.refresh()).isNotEqualTo(original.refresh());
        var sid = sessionId(original);
        assertThat(sessionId(rotated)).isEqualTo(sid);
        mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(original.refresh()))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value("REFRESH_TOKEN_INVALID"));
        assertThat(sessions.findById(sid).orElseThrow().getRevokedAt()).isNotNull();
        denied(rotated.access(), "SESSION_REVOKED");
        mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(rotated.refresh()))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void concurrentRefreshSucceedsOnceAndRevokesSession() throws Exception {
        Pair original = login(user());
        var start = new CountDownLatch(1);
        String body = json.writeValueAsString(new RefreshRequest(original.refresh()));
        try (var executor = Executors.newFixedThreadPool(2)) {
            Callable<Integer> action = () -> {
                start.await();
                return mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(body)).andReturn().getResponse().getStatus();
            };
            var first = executor.submit(action);
            var second = executor.submit(action);
            start.countDown();
            assertThat(List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(200, 401);
        }
        assertThat(sessions.findById(sessionId(original)).orElseThrow().getRevokedAt()).isNotNull();
        denied(original.access(), "SESSION_REVOKED");
    }

    @Test
    void logoutIsImmediateIdempotentAndDoesNotRevokeOtherDevice() throws Exception {
        User user = user();
        Pair first = login(user);
        Pair second = login(user);
        for (int i = 0; i < 2; i++) {
            mvc.perform(post("/api/v1/auth/api/logout").contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(new RefreshRequest(first.refresh()))))
                    .andExpect(status().isNoContent());
        }
        mvc.perform(post("/api/v1/auth/api/logout")).andExpect(status().isNoContent());
        denied(first.access(), "SESSION_REVOKED");
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + second.access()))
                .andExpect(status().isOk());
    }

    @Test
    void passwordChangeImmediatelyRevokesExistingAccessAndRefresh() throws Exception {
        User user = user();
        Pair first = login(user);
        Pair second = login(user);
        mvc.perform(put("/api/v1/users/me/password").header("Authorization", "Bearer " + first.access())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new ChangePasswordRequest(PASSWORD, "another-password-12345"))))
                .andExpect(status().isNoContent());
        denied(first.access(), "SESSION_REVOKED");
        denied(second.access(), "SESSION_REVOKED");
        mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(second.refresh()))))
                .andExpect(status().isUnauthorized());
        invalidLogin(user.getEmail(), PASSWORD);
        mvc.perform(post("/api/v1/auth/api/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new LoginRequest(user.getEmail(), "another-password-12345"))))
                .andExpect(status().isOk());
    }

    @Test
    void emailChangeAndAccountDisableInvalidateAlreadyIssuedAccess() throws Exception {
        User user = user();
        Pair original = login(user);
        String newEmail = UUID.randomUUID() + "@example.com";
        mvc.perform(put("/api/v1/users/me").header("Authorization", "Bearer " + original.access())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new UpdateProfileRequest(newEmail, "Новое имя", PASSWORD, user.getVersion()))))
                .andExpect(status().isOk());
        denied(original.access(), "SESSION_REVOKED");
        Pair updated = login(users.findById(user.getId()).orElseThrow());
        mvc.perform(delete("/api/v1/users/me").header("Authorization", "Bearer " + updated.access())
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(new DeleteAccountRequest(PASSWORD))))
                .andExpect(status().isNoContent());
        denied(updated.access(), "SESSION_REVOKED");
    }

    @Test
    void webLoginRefreshLogoutUseProtectedCookieAndCsrf() throws Exception {
        User user = user();
        String body = json.writeValueAsString(new LoginRequest(user.getEmail(), PASSWORD));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden()).andExpect(jsonPath("code").value("CSRF_TOKEN_INVALID"));
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andExpect(jsonPath("refreshToken").doesNotExist())
                .andExpect(header().string("Cache-Control", "no-store")).andReturn().getResponse();
        String cookieHeader = login.getHeader("Set-Cookie");
        assertThat(cookieHeader).contains("HttpOnly", "Secure", "SameSite=Lax", "Path=/api/v1/auth")
                .doesNotContain("Domain=");
        Cookie cookie = login.getCookie("refresh_token");
        assertThat(cookie).isNotNull();
        mvc.perform(post("/api/v1/auth/refresh").cookie(cookie)).andExpect(status().isForbidden());
        var refreshed = mvc.perform(post("/api/v1/auth/refresh").cookie(cookie).with(csrf()))
                .andExpect(status().isOk()).andExpect(jsonPath("refreshToken").doesNotExist()).andReturn().getResponse();
        Cookie next = refreshed.getCookie("refresh_token");
        assertThat(next.getValue()).isNotEqualTo(cookie.getValue());
        String access = json.readTree(refreshed.getContentAsString()).get("accessToken").asText();
        mvc.perform(get("/api/v1/users/me").cookie(next)).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/logout").cookie(next).with(csrf()))
                .andExpect(status().isNoContent()).andExpect(header().string("Set-Cookie",
                        org.hamcrest.Matchers.containsString("Max-Age=0")));
        denied(access, "SESSION_REVOKED");
        mvc.perform(post("/api/v1/auth/logout").with(csrf())).andExpect(status().isNoContent());
    }

    @Test
    void refreshTransportsCannotBeMixedAndApiIgnoresCookies() throws Exception {
        Pair api = login(user());
        mvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refresh_token", api.refresh())).with(csrf()))
                .andExpect(status().isUnauthorized());
        assertThat(sessions.findById(sessionId(api)).orElseThrow().getRevokedAt()).isNull();
        User webUser = user();
        var web = mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new LoginRequest(webUser.getEmail(), PASSWORD))))
                .andExpect(status().isOk()).andReturn().getResponse().getCookie("refresh_token");
        mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(web.getValue())))).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/api/refresh").cookie(web)).andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/auth/api/logout").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(web.getValue())))).andExpect(status().isNoContent());
        mvc.perform(post("/api/v1/auth/refresh").cookie(web).with(csrf())).andExpect(status().isOk());
    }

    @Test
    void expiredRefreshCannotBeUsed() throws Exception {
        Pair pair = login(user());
        UUID sid = sessionId(pair);
        jdbc.update("update refresh_tokens set created_at = current_timestamp - interval '1 hour', "
                + "expires_at = current_timestamp - interval '1 second' where session_id = ?", sid);
        mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(pair.refresh())))).andExpect(status().isUnauthorized());
    }

    @Test
    void expiredSessionBlocksBothAccessAndRefresh() throws Exception {
        Pair pair = login(user());
        jdbc.update("update auth_sessions set created_at = current_timestamp - interval '1 hour', "
                + "expires_at = current_timestamp - interval '1 second' where id = ?", sessionId(pair));
        denied(pair.access(), "SESSION_REVOKED");
        mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(pair.refresh()))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value("REFRESH_TOKEN_INVALID"));
    }

    @Test
    void invalidRefreshAndEmptyLogoutHaveSafeResponses() throws Exception {
        for (String token : List.of("malformed", "A".repeat(43))) {
            mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(new RefreshRequest(token))))
                    .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value("REFRESH_TOKEN_INVALID"));
        }
        mvc.perform(post("/api/v1/auth/refresh").with(csrf()))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value("REFRESH_TOKEN_INVALID"));
        mvc.perform(post("/api/v1/auth/api/logout").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void jwtRejectsExpiredWrongAudienceIssuerSignatureAndMalformedClaims() throws Exception {
        Pair pair = login(user());
        Jwt jwt = decoder.decode(pair.access());
        denied(signed(jwt.getSubject(), jwt.getClaimAsString("sid"), properties.issuer(), properties.audience(),
                Instant.now().minusSeconds(5)), "ACCESS_TOKEN_EXPIRED");
        denied(signed(jwt.getSubject(), jwt.getClaimAsString("sid"), "other-issuer", properties.audience(),
                Instant.now().plusSeconds(60)), "ACCESS_TOKEN_INVALID");
        denied(signed(jwt.getSubject(), jwt.getClaimAsString("sid"), properties.issuer(), "other-audience",
                Instant.now().plusSeconds(60)), "ACCESS_TOKEN_INVALID");
        denied(signed("not-a-uuid", jwt.getClaimAsString("sid"), properties.issuer(), properties.audience(),
                Instant.now().plusSeconds(60)), "ACCESS_TOKEN_INVALID");
        denied(signed(jwt.getSubject(), UUID.randomUUID().toString(), properties.issuer(), properties.audience(),
                Instant.now().plusSeconds(60)), "SESSION_REVOKED");
        denied(signed(user().getId().toString(), jwt.getClaimAsString("sid"), properties.issuer(), properties.audience(),
                Instant.now().plusSeconds(60)), "SESSION_REVOKED");
        String[] parts = pair.access().split("\\.");
        char first = parts[2].charAt(0);
        denied(parts[0] + "." + parts[1] + "." + (first == 'A' ? 'B' : 'A') + parts[2].substring(1), "ACCESS_TOKEN_INVALID");
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Basic dXNlcjpwYXNz"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value("UNAUTHORIZED"));
    }

    @Test
    void corsAllowsConfiguredOriginAndRejectsOthers() throws Exception {
        mvc.perform(options("/api/v1/auth/login").header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "POST").header("Access-Control-Request-Headers", "content-type,x-xsrf-token"))
                .andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
        mvc.perform(options("/api/v1/auth/login").header("Origin", "https://unknown.example")
                .header("Access-Control-Request-Method", "POST")).andExpect(status().isForbidden());
    }

    @Test
    void missingAudienceAndWrongSessionClaimTypeReturnUnauthorized() throws Exception {
        User user = user();
        Pair pair = login(user);
        for (boolean missingAudience : List.of(true, false)) {
            var builder = JwtClaimsSet.builder().issuer(properties.issuer()).subject(user.getId().toString())
                    .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).id(UUID.randomUUID().toString());
            if (missingAudience) {
                builder.claim("sid", sessionId(pair).toString());
            } else {
                builder.audience(List.of(properties.audience())).claim("sid", List.of("unexpected"));
            }
            String access = encoder.encode(JwtEncoderParameters.from(
                    JwsHeader.with(SignatureAlgorithm.RS256).build(), builder.build())).getTokenValue();
            denied(access, "ACCESS_TOKEN_INVALID");
        }
    }

    private String signed(String subject, String sid, String issuer, String audience, Instant expiration) {
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(subject).audience(List.of(audience))
                .issuedAt(Instant.now().minusSeconds(60)).expiresAt(expiration).id(UUID.randomUUID().toString()).claim("sid", sid).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).getTokenValue();
    }

    private Pair login(User user) throws Exception {
        var response = mvc.perform(post("/api/v1/auth/api/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new LoginRequest(user.getEmail(), PASSWORD))))
                .andExpect(status().isOk()).andExpect(jsonPath("tokenType").value("Bearer"))
                .andExpect(jsonPath("expiresIn").value(900)).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().doesNotExist("Set-Cookie")).andReturn().getResponse();
        return pair(response.getContentAsString());
    }

    private Pair refresh(String refresh) throws Exception {
        var response = mvc.perform(post("/api/v1/auth/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RefreshRequest(refresh)))).andExpect(status().isOk()).andReturn().getResponse();
        return pair(response.getContentAsString());
    }

    private Pair pair(String body) throws Exception {
        var node = json.readTree(body);
        return new Pair(node.get("accessToken").asText(), node.get("refreshToken").asText());
    }

    private UUID sessionId(Pair pair) { return UUID.fromString(decoder.decode(pair.access()).getClaimAsString("sid")); }

    private void invalidLogin(String email, String password) throws Exception {
        mvc.perform(post("/api/v1/auth/api/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new LoginRequest(email, password))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value("INVALID_CREDENTIALS"));
    }

    private void denied(String access, String code) throws Exception {
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value(code))
                .andExpect(header().exists("X-Trace-Id"));
    }

    private RequestPostProcessor csrf() throws Exception {
        var response = mvc.perform(get("/api/v1/auth/csrf")).andExpect(status().isOk()).andReturn().getResponse();
        var cookie = response.getCookie("XSRF-TOKEN");
        String token = json.readTree(response.getContentAsString()).get("token").asText();
        return request -> {
            var cookies = new java.util.ArrayList<Cookie>();
            if (request.getCookies() != null) { cookies.addAll(List.of(request.getCookies())); }
            cookies.add(cookie);
            request.setCookies(cookies.toArray(Cookie[]::new));
            request.addHeader("X-XSRF-TOKEN", token);
            return request;
        };
    }

    private User user() { return users.saveAndFlush(new User(UUID.randomUUID() + "@example.com", passwords.encode(PASSWORD), "Артём")); }
    private record Pair(String access, String refresh) { }
}
