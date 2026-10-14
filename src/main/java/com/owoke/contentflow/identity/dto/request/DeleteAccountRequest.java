package com.owoke.contentflow.identity.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record DeleteAccountRequest(
        @NotBlank(message = "Текущий пароль обязателен")
        @Size(max = 128, message = "Пароль должен содержать не более 128 символов") String currentPassword
) {}
