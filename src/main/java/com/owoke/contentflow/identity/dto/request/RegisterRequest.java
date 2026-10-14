package com.owoke.contentflow.identity.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Email обязателен")
        @Email(message = "Некорректный формат email")
        @Size(max = 255, message = "Email должен содержать не более 255 символов") String email,

        @NotBlank(message = "Пароль обязателен")
        @Size(min = 8, max = 128, message = "Пароль должен содержать от 12 до 128 символов") String password,

        @NotBlank(message = "Имя обязательно")
        @Size(min = 2, max = 100, message = "Имя должно содержать от 2 до 100 символов") String displayName) {

}
