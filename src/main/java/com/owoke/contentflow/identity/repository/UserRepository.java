package com.owoke.contentflow.identity.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import jakarta.persistence.LockModeType;

import com.owoke.contentflow.identity.entity.User;

public interface UserRepository extends JpaRepository<User, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id = :id")
    Optional<User> findForUpdate(UUID id);
    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);

    Optional<User> findByTelegramUserId(Long telegramUserId);
}
