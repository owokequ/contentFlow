package com.owoke.contentflow.identity.exception;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;

public class AccountDisabledException extends BusinessException {
    public AccountDisabledException() { super(ErrorCode.ACCOUNT_DISABLED); }
}
