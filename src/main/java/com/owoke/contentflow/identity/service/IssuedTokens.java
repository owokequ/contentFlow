package com.owoke.contentflow.identity.service;

import java.time.Instant;
import com.owoke.contentflow.identity.dto.response.AccessTokenResponse;
import com.owoke.contentflow.identity.dto.response.ApiTokenResponse;

public record IssuedTokens(String accessToken, String refreshToken, long expiresIn, Instant sessionExpiresAt) {
    public AccessTokenResponse webResponse() { return new AccessTokenResponse(accessToken, "Bearer", expiresIn); }
    public ApiTokenResponse apiResponse() { return new ApiTokenResponse(accessToken, "Bearer", expiresIn, refreshToken); }
    @Override public String toString() { return "IssuedTokens[redacted]"; }
}
