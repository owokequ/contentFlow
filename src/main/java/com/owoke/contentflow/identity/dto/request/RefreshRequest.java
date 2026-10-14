package com.owoke.contentflow.identity.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshRequest(@NotBlank(message = "Укажи refresh-токен") @Size(max = 256) String refreshToken) { }
