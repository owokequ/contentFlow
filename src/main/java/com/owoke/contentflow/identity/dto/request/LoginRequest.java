package com.owoke.contentflow.identity.dto.request;

import jakarta.validation.constraints.*;

public record LoginRequest(
        @NotBlank(message = "Укажи email") @Email(message = "Некорректный email") @Size(max = 255) String email,
        @NotBlank(message = "Укажи пароль") @Size(max = 128) String password) { }
