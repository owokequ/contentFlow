package com.owoke.contentflow.identity.dto.response;

public record ApiTokenResponse(String accessToken, String tokenType, long expiresIn, String refreshToken) { }
