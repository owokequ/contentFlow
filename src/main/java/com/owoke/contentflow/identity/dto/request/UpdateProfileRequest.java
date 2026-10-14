package com.owoke.contentflow.identity.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

public record UpdateProfileRequest(
        @NotBlank(message = "Email обязателен") @Email(message = "Некорректный формат email")
        @Size(max = 255, message = "Email должен содержать не более 255 символов") String email,
        @NotBlank(message = "Имя обязательно")
        @Size(min = 2, max = 100, message = "Имя должно содержать от 2 до 100 символов") String displayName,
        @NotBlank(message = "Текущий пароль обязателен")
        @Size(max = 128, message = "Пароль должен содержать не более 128 символов") String currentPassword,
        @NotNull(message = "Версия профиля обязательна")
        @PositiveOrZero(message = "Версия должна быть неотрицательной") Long version
) {}
