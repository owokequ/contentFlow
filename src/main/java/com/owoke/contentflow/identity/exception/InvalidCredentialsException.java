package com.owoke.contentflow.identity.exception;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;

public class InvalidCredentialsException extends BusinessException {
    public InvalidCredentialsException() { super(ErrorCode.INVALID_CREDENTIALS); }
}
