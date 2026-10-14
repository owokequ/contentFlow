package com.owoke.contentflow.identity.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank(message = "Текущий пароль обязателен")
        @Size(max = 128, message = "Пароль должен содержать не более 128 символов") String currentPassword,
        @NotBlank(message = "Новый пароль обязателен")
        @Size(min = 12, max = 128, message = "Пароль должен содержать от 12 до 128 символов") String newPassword
) {}
