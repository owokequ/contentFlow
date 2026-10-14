package com.owoke.contentflow.identity.repository;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import com.owoke.contentflow.identity.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    // Read an ID before locking; do not cache a stale token entity in the persistence context.
    @Query("select t.sessionId from RefreshToken t where t.tokenHash = :hash")
    Optional<UUID> findSessionIdByHash(String hash);
    Optional<RefreshToken> findByTokenHash(String hash);
}
