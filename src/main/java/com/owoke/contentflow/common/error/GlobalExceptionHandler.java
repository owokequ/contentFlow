package com.owoke.contentflow.common.error;

import java.util.List;

import org.hibernate.exception.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final ErrorResponseFactory errors;

    public GlobalExceptionHandler(ErrorResponseFactory errors) { this.errors = errors; }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Object> handleBusiness(BusinessException exception, HttpServletRequest request) {
        return errors.response(request, exception.code(), exception.fieldErrors(), new HttpHeaders());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Object> handleIntegrity(DataIntegrityViolationException exception,
            HttpServletRequest request) {
        ErrorCode code = ErrorCode.DATA_CONFLICT;
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException violation) {
                String name = violation.getConstraintName();
                if ("users_email_key".equals(name) || "uq_users_email".equals(name)) {
                    code = ErrorCode.EMAIL_ALREADY_EXISTS;
                } else if ("users_telegram_user_id_key".equals(name)
                        || "uq_users_telegram_user_id".equals(name)) {
                    code = ErrorCode.TELEGRAM_ALREADY_LINKED;
                }
                break;
            }
        }
        return errors.response(request, code, List.of(), new HttpHeaders());
    }

    @ExceptionHandler(OptimisticLockingFailureException.class)
    public ResponseEntity<Object> handleConflict(OptimisticLockingFailureException exception,
            HttpServletRequest request) {
        return errors.response(request, ErrorCode.VERSION_CONFLICT, List.of(), new HttpHeaders());
    }

    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    public ResponseEntity<Object> handleConstraintValidation(
            jakarta.validation.ConstraintViolationException exception, HttpServletRequest request) {
        List<FieldViolation> fields = exception.getConstraintViolations().stream()
                .map(v -> new FieldViolation(v.getPropertyPath().toString(), v.getMessage()))
                .sorted(java.util.Comparator.comparing(FieldViolation::field))
                .toList();
        return errors.response(request, ErrorCode.VALIDATION_ERROR, fields, new HttpHeaders());
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthentication(AuthenticationException exception,
            HttpServletRequest request) {
        return errors.response(request, ErrorCode.INVALID_CREDENTIALS, List.of(), new HttpHeaders());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccess(AccessDeniedException exception, HttpServletRequest request) {
        return errors.response(request, ErrorCode.ACCESS_DENIED, List.of(), new HttpHeaders());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleUnexpected(Exception exception, HttpServletRequest request) {
        ResponseEntity<Object> response = errors.response(request, ErrorCode.INTERNAL_ERROR,
                List.of(), new HttpHeaders());
        ApiError body = (ApiError) response.getBody();
        log.error("Unhandled API error: traceId={}, exceptionType={}", body.traceId(),
                exception.getClass().getName());
        return response;
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException exception,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<FieldViolation> fields = exception.getBindingResult().getFieldErrors().stream()
                .map(e -> new FieldViolation(e.getField(), e.getDefaultMessage()))
                .sorted(java.util.Comparator.comparing(FieldViolation::field))
                .toList();
        return errors.response(((ServletWebRequest) request).getRequest(),
                ErrorCode.VALIDATION_ERROR, fields, headers);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception exception, Object body,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ErrorCode code = switch (status.value()) {
            case 400 -> ErrorCode.INVALID_REQUEST;
            case 404 -> ErrorCode.RESOURCE_NOT_FOUND;
            case 405 -> ErrorCode.METHOD_NOT_ALLOWED;
            case 406 -> ErrorCode.NOT_ACCEPTABLE;
            case 415 -> ErrorCode.UNSUPPORTED_MEDIA_TYPE;
            default -> ErrorCode.INTERNAL_ERROR;
        };
        return errors.response(((ServletWebRequest) request).getRequest(), code, List.of(), headers);
    }
}
