package com.owoke.contentflow.identity.dto.response;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(UUID id, String email, String displayName, Long telegramUserId,
        Long version, Instant createdAt, Instant updatedAt) {}
