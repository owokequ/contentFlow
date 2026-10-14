package com.owoke.contentflow.identity;

import static org.assertj.core.api.Assertions.assertThat;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.owoke.contentflow.PostgresIntegrationTest;
import com.owoke.contentflow.identity.dto.request.ChangePasswordRequest;
import com.owoke.contentflow.identity.dto.request.DeleteAccountRequest;
import com.owoke.contentflow.identity.dto.request.RegisterRequest;
import com.owoke.contentflow.identity.dto.request.UpdateProfileRequest;
import com.owoke.contentflow.identity.entity.AuthSession;
import com.owoke.contentflow.identity.entity.User;
import com.owoke.contentflow.identity.entity.UserStatus;
import com.owoke.contentflow.identity.repository.AuthSessionRepository;
import com.owoke.contentflow.identity.repository.UserRepository;

import tools.jackson.databind.json.JsonMapper;

class IdentityApiIntegrationTests extends PostgresIntegrationTest {
    private static final String PASSWORD = "test-password-12345";
    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired UserRepository users;
    @Autowired AuthSessionRepository sessions;
    @Autowired PasswordEncoder passwords;

    @Test
    void registrationNormalizesDataAndDoesNotExposeSecrets() throws Exception {
        String email = email();
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RegisterRequest(email.toUpperCase(), PASSWORD, "  Артём  "))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("email").value(email))
                .andExpect(jsonPath("displayName").value("Артём"))
                .andExpect(jsonPath("createdAt").isNotEmpty())
                .andExpect(jsonPath("passwordHash").doesNotExist())
                .andExpect(jsonPath("password").doesNotExist());
        User user = users.findByEmail(email).orElseThrow();
        assertThat(user.getPasswordHash()).isNotEqualTo(PASSWORD);
        assertThat(passwords.matches(PASSWORD, user.getPasswordHash())).isTrue();
        assertThat(user.getVersion()).isZero();
    }

    @Test
    void duplicateEmailReturnsConflict() throws Exception {
        User user = createUser();
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RegisterRequest(user.getEmail(), PASSWORD, "Артём"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("code").value("EMAIL_ALREADY_EXISTS"))
                .andExpect(jsonPath("traceId").isNotEmpty())
                .andExpect(header().exists("X-Trace-Id"));
    }

    @Test
    void invalidRequestAndMalformedJsonReturnSafeErrors() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RegisterRequest("invalid", "secret", "a"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("fieldErrors").isArray())
                .andExpect(jsonPath("fieldErrors[0].rejectedValue").doesNotExist());
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content("{"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("code").value("INVALID_REQUEST"));
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new RegisterRequest(email(), PASSWORD, " а "))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("code").value("VALIDATION_ERROR"));
    }

    @Test
    void anonymousAndInvalidBearerReturnJsonUnauthorized() throws Exception {
        mvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("code").value("UNAUTHORIZED"));
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer invalid"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("code").value("ACCESS_TOKEN_INVALID"));
    }

    @Test
    void currentProfileUsesAuthenticatedUserAndDoesNotExposeHash() throws Exception {
        User first = createUser();
        User second = createUser();
        mvc.perform(get("/api/v1/users/me").param("userId", second.getId().toString())
                .with(bearer(first.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("id").value(first.getId().toString()))
                .andExpect(jsonPath("passwordHash").doesNotExist());
    }

    @Test
    void updateRequiresAuthenticationAndCurrentPassword() throws Exception {
        User user = createUser();
        String body = json.writeValueAsString(new UpdateProfileRequest(user.getEmail(), "Новое имя",
                PASSWORD, user.getVersion()));
        mvc.perform(put("/api/v1/users/me")
                .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("code").value("UNAUTHORIZED"));
        mvc.perform(put("/api/v1/users/me").with(bearer(user.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new UpdateProfileRequest(user.getEmail(), "Новое имя",
                        "wrong-password", user.getVersion()))))
                .andExpect(status().isUnauthorized());
        assertThat(users.findById(user.getId()).orElseThrow().getDisplayName()).isEqualTo("Артём");
    }

    @Test
    void updateChangesOnlyAllowedFieldsAndDetectsStaleVersions() throws Exception {
        User user = createUser();
        mvc.perform(put("/api/v1/users/me").with(bearer(user.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new UpdateProfileRequest(user.getEmail(), "  Новое имя  ",
                        PASSWORD, user.getVersion()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("displayName").value("Новое имя"))
                .andExpect(jsonPath("version").value(1));
        User updated = users.findById(user.getId()).orElseThrow();
        assertThat(updated.getPasswordHash()).isEqualTo(user.getPasswordHash());
        assertThat(updated.getStatus()).isEqualTo(UserStatus.ACTIVE);
        mvc.perform(put("/api/v1/users/me").with(bearer(user.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new UpdateProfileRequest(user.getEmail(), "Старый запрос",
                        PASSWORD, user.getVersion()))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("code").value("VERSION_CONFLICT"));
    }

    @Test
    void changingEmailRevokesSessionsAndUsesNewCredentials() throws Exception {
        User user = createUser();
        AuthSession session = createSession(user);
        var originalAuthentication = bearer(user.getEmail(), PASSWORD);
        String newEmail = email();
        mvc.perform(put("/api/v1/users/me").with(bearer(user.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new UpdateProfileRequest(newEmail, "Артём",
                        PASSWORD, user.getVersion()))))
                .andExpect(status().isOk()).andExpect(jsonPath("email").value(newEmail));
        assertThat(sessions.findById(session.getId()).orElseThrow().getRevokedAt()).isNotNull();
        mvc.perform(get("/api/v1/users/me").with(originalAuthentication))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/users/me").with(bearer(newEmail, PASSWORD)))
                .andExpect(status().isOk());
    }

    @Test
    void conflictingEmailDoesNotModifyProfile() throws Exception {
        User first = createUser();
        User second = createUser();
        mvc.perform(put("/api/v1/users/me").with(bearer(first.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new UpdateProfileRequest(second.getEmail(), "Новое имя",
                        PASSWORD, first.getVersion()))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("code").value("EMAIL_ALREADY_EXISTS"));
        assertThat(users.findById(first.getId()).orElseThrow().getEmail()).isEqualTo(first.getEmail());
    }

    @Test
    void changingPasswordRevokesSessionsAndInvalidatesOldPassword() throws Exception {
        User user = createUser();
        AuthSession session = createSession(user);
        var originalAuthentication = bearer(user.getEmail(), PASSWORD);
        String newPassword = "new-password-12345";
        mvc.perform(put("/api/v1/users/me/password").with(bearer(user.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new ChangePasswordRequest(PASSWORD, newPassword))))
                .andExpect(status().isNoContent());
        assertThat(sessions.findById(session.getId()).orElseThrow().getRevokedAt()).isNotNull();
        mvc.perform(get("/api/v1/users/me").with(originalAuthentication))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/users/me").with(bearer(user.getEmail(), newPassword)))
                .andExpect(status().isOk());
    }

    @Test
    void deleteDisablesAccountAndRevokesSessions() throws Exception {
        User user = createUser();
        AuthSession session = createSession(user);
        var originalAuthentication = bearer(user.getEmail(), PASSWORD);
        mvc.perform(delete("/api/v1/users/me").with(bearer(user.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new DeleteAccountRequest(PASSWORD))))
                .andExpect(status().isNoContent());
        assertThat(users.findById(user.getId()).orElseThrow().getStatus()).isEqualTo(UserStatus.DISABLED);
        assertThat(sessions.findById(session.getId()).orElseThrow().getRevokedAt()).isNotNull();
        mvc.perform(get("/api/v1/users/me").with(originalAuthentication))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void csrfEndpointReturnsCookieAndToken() throws Exception {
        mvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("headerName").value("X-XSRF-TOKEN"))
                .andExpect(jsonPath("token").isNotEmpty())
                .andExpect(header().exists("Set-Cookie"));
    }

    private User createUser() {
        return users.saveAndFlush(new User(email(), passwords.encode(PASSWORD), "Артём"));
    }

    @Test
    void unsupportedContentTypeMethodAndUnknownPathHaveConsistentErrors() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.TEXT_PLAIN).content("invalid"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("code").value("UNSUPPORTED_MEDIA_TYPE"));
        User user = createUser();
        mvc.perform(post("/api/v1/users/me").with(bearer(user.getEmail(), PASSWORD))
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().exists("Allow"))
                .andExpect(jsonPath("code").value("METHOD_NOT_ALLOWED"));
        mvc.perform(get("/api/v1/unknown").with(bearer(user.getEmail(), PASSWORD)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("code").value("RESOURCE_NOT_FOUND"));
    }

    @Test
    void concurrentRegistrationsReturnCreatedAndConflict() throws Exception {
        String email = email();
        String body = json.writeValueAsString(new RegisterRequest(email, PASSWORD, "Артём"));
        var start = new java.util.concurrent.CountDownLatch(1);
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Integer> registration = () -> {
                start.await();
                return mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(body)).andReturn().getResponse().getStatus();
            };
            var first = executor.submit(registration);
            var second = executor.submit(registration);
            start.countDown();
            assertThat(java.util.List.of(first.get(20, java.util.concurrent.TimeUnit.SECONDS),
                    second.get(20, java.util.concurrent.TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(201, 409);
        }
        assertThat(users.findByEmail(email)).isPresent();
    }

    private RequestPostProcessor bearer(String email, String password) throws Exception {
        var response = mvc.perform(post("/api/v1/auth/api/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new com.owoke.contentflow.identity.dto.request.LoginRequest(email, password))))
                .andExpect(status().isOk()).andReturn().getResponse();
        String token = json.readTree(response.getContentAsString()).get("accessToken").asText();
        return request -> { request.addHeader("Authorization", "Bearer " + token); return request; };
    }
    private AuthSession createSession(User user) {
        AuthSession session = new AuthSession();
        session.setUserId(user.getId());
        session.setExpiresAt(Instant.now().plusSeconds(3600));
        return sessions.saveAndFlush(session);
    }

    private String email() { return UUID.randomUUID() + "@example.com"; }
}


