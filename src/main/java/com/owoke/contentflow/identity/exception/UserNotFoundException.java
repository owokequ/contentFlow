package com.owoke.contentflow.identity.exception;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;

public class UserNotFoundException extends BusinessException {
    public UserNotFoundException() { super(ErrorCode.USER_NOT_FOUND); }
}
