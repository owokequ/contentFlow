package com.owoke.contentflow.identity.exception;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;

public class RefreshTokenRejectedException extends BusinessException {
    public RefreshTokenRejectedException() { super(ErrorCode.REFRESH_TOKEN_INVALID); }
}
