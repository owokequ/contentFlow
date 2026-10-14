package com.owoke.contentflow.identity.exception;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;

public class ProfileVersionConflictException extends BusinessException {
    public ProfileVersionConflictException() { super(ErrorCode.VERSION_CONFLICT); }
}
