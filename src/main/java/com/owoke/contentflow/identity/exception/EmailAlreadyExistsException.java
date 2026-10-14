package com.owoke.contentflow.identity.exception;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;

public class EmailAlreadyExistsException extends BusinessException {

    public EmailAlreadyExistsException(String message) {
        super(ErrorCode.EMAIL_ALREADY_EXISTS);
    }

}
