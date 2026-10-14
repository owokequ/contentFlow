package com.owoke.contentflow.identity.repository;

import java.time.Instant;
import java.util.UUID;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.owoke.contentflow.identity.entity.AuthSession;

public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {
    @Query("select s.userId from AuthSession s where s.id = :id")
    Optional<UUID> findUserIdById(UUID id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from AuthSession s where s.id = :id")
    Optional<AuthSession> findForUpdate(UUID id);
    @Modifying
    @Query("update AuthSession s set s.revokedAt = :now where s.userId = :userId and s.revokedAt is null")
    int revokeAllForUser(@Param("userId") UUID userId, @Param("now") Instant now);
}
