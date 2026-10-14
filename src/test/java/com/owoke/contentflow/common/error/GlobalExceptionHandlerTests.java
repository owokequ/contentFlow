package com.owoke.contentflow.common.error;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.SQLException;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mock.web.MockHttpServletRequest;

class GlobalExceptionHandlerTests {
    private final GlobalExceptionHandler handler = new GlobalExceptionHandler(new ErrorResponseFactory());
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/register");

    @Test
    void emailConstraintConflictIsRecognizedWithoutLeakingDatabaseDetails() {
        var violation = new ConstraintViolationException("sensitive database details",
                new SQLException("sensitive SQL", "23505"), "users_email_key");
        var response = handler.handleIntegrity(new DataIntegrityViolationException("internal", violation), request);
        ApiError error = (ApiError) response.getBody();
        assertThat(response.getStatusCode().value()).isEqualTo(409);
        assertThat(error.code()).isEqualTo("EMAIL_ALREADY_EXISTS");
        assertThat(error.message()).doesNotContain("sensitive", "SQL");
    }

    @Test
    void otherConstraintsAreNotMisreportedAsDuplicateEmail() {
        var violation = new ConstraintViolationException("foreign key",
                new SQLException("internal", "23503"), "fk_auth_sessions_user");
        var response = handler.handleIntegrity(new DataIntegrityViolationException("internal", violation), request);
        assertThat(((ApiError) response.getBody()).code()).isEqualTo("DATA_CONFLICT");
    }

    @Test
    void unexpectedErrorsHaveSafeMessageAndTraceId() {
        var response = handler.handleUnexpected(new RuntimeException("password=secret"), request);
        ApiError error = (ApiError) response.getBody();
        assertThat(response.getStatusCode().value()).isEqualTo(500);
        assertThat(error.message()).doesNotContain("secret", "password");
        assertThat(response.getHeaders().getFirst("X-Trace-Id")).isEqualTo(error.traceId());
    }
}
