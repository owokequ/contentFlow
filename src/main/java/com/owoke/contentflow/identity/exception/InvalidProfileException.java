package com.owoke.contentflow.identity.exception;

import java.util.List;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;
import com.owoke.contentflow.common.error.FieldViolation;

public class InvalidProfileException extends BusinessException {
    public InvalidProfileException(String field, String message) {
        super(ErrorCode.VALIDATION_ERROR, List.of(new FieldViolation(field, message)));
    }
}
