package com.owoke.contentflow.identity.dto.request;

import jakarta.validation.constraints.Size;

public record LogoutRequest(@Size(max = 256) String refreshToken) { }
