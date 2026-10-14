package com.owoke.contentflow.identity.dto.response;

public record AccessTokenResponse(String accessToken, String tokenType, long expiresIn) { }
