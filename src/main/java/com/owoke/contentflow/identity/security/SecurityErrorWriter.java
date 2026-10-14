package com.owoke.contentflow.identity.security;

import java.io.IOException;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import com.owoke.contentflow.common.error.ErrorCode;
import com.owoke.contentflow.common.error.ErrorResponseFactory;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

@Component
public class SecurityErrorWriter {
    private final ErrorResponseFactory errors;
    private final JsonMapper json;

    public SecurityErrorWriter(ErrorResponseFactory errors, JsonMapper json) {
        this.errors = errors;
        this.json = json;
    }

    public void write(HttpServletRequest request, HttpServletResponse response, ErrorCode code)
            throws IOException {
        var body = errors.create(request, code, List.of());
        response.setStatus(code.status().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader(ErrorResponseFactory.TRACE_HEADER, body.traceId());
        response.getWriter().write(json.writeValueAsString(body));
    }
}
