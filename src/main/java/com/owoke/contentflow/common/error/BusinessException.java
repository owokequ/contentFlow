package com.owoke.contentflow.common.error;

import java.util.List;

public class BusinessException extends RuntimeException {
    private final ErrorCode code;
    private final List<FieldViolation> fieldErrors;

    public BusinessException(ErrorCode code) {
        this(code, List.of());
    }

    public BusinessException(ErrorCode code, List<FieldViolation> fieldErrors) {
        super(code.message());
        this.code = code;
        this.fieldErrors = List.copyOf(fieldErrors);
    }

    public ErrorCode code() { return code; }
    public List<FieldViolation> fieldErrors() { return fieldErrors; }
}
