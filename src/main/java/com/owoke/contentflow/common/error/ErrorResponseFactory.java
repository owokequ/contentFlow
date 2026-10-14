package com.owoke.contentflow.common.error;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class ErrorResponseFactory {
    public static final String TRACE_HEADER = "X-Trace-Id";
    private static final String TRACE_ATTRIBUTE = ErrorResponseFactory.class.getName() + ".traceId";

    public ApiError create(HttpServletRequest request, ErrorCode code, List<FieldViolation> fields) {
        String traceId = (String) request.getAttribute(TRACE_ATTRIBUTE);
        if (traceId == null) {
            traceId = UUID.randomUUID().toString();
            request.setAttribute(TRACE_ATTRIBUTE, traceId);
        }
        return new ApiError(Instant.now(), code.status().value(), code.name(), code.message(),
                request.getRequestURI(), traceId, List.copyOf(fields));
    }

    public ResponseEntity<Object> response(HttpServletRequest request, ErrorCode code,
            List<FieldViolation> fields, HttpHeaders originalHeaders) {
        ApiError body = create(request, code, fields);
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(originalHeaders);
        headers.set(TRACE_HEADER, body.traceId());
        return new ResponseEntity<>(body, headers, code.status());
    }
}
