package com.owoke.contentflow.identity.dto.response;

import java.time.Instant;
import java.util.UUID;

public record RegisterResponse(
        UUID id,
        String email,
        String displayName,
        Instant createdAt) {

}
