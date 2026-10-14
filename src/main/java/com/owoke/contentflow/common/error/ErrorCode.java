package com.owoke.contentflow.common.error;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    VALIDATION_ERROR(HttpStatus.BAD_REQUEST, "Некорректные данные"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "Некорректный запрос"),
    EMAIL_ALREADY_EXISTS(HttpStatus.CONFLICT, "Email уже используется"),
    TELEGRAM_ALREADY_LINKED(HttpStatus.CONFLICT, "Telegram уже привязан к другому аккаунту"),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "Пользователь не найден"),
    ACCOUNT_DISABLED(HttpStatus.FORBIDDEN, "Аккаунт отключён"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Необходима аутентификация"),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Неверные учётные данные"),
    ACCESS_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "Недействительный access-токен"),
    ACCESS_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "Срок действия access-токена истёк"),
    REFRESH_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "Недействительный refresh-токен"),
    SESSION_REVOKED(HttpStatus.UNAUTHORIZED, "Сессия недействительна или отозвана"),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "Недостаточно прав"),
    CSRF_TOKEN_INVALID(HttpStatus.FORBIDDEN, "Отсутствует или недействителен CSRF-токен"),
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, "Ресурс не найден"),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "HTTP-метод не поддерживается"),
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Формат тела запроса не поддерживается"),
    NOT_ACCEPTABLE(HttpStatus.NOT_ACCEPTABLE, "Запрошенный формат ответа не поддерживается"),
    DATA_CONFLICT(HttpStatus.CONFLICT, "Операция конфликтует с текущими данными"),
    VERSION_CONFLICT(HttpStatus.CONFLICT, "Данные уже изменены другим запросом"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Внутренняя ошибка сервера");

    private final HttpStatus status;
    private final String message;

    ErrorCode(HttpStatus status, String message) {
        this.status = status;
        this.message = message;
    }

    public HttpStatus status() { return status; }
    public String message() { return message; }
}
