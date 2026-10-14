package com.owoke.contentflow.identity.service;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.owoke.contentflow.identity.dto.request.ChangePasswordRequest;
import com.owoke.contentflow.identity.dto.request.DeleteAccountRequest;
import com.owoke.contentflow.identity.dto.request.UpdateProfileRequest;
import com.owoke.contentflow.identity.dto.response.UserResponse;
import com.owoke.contentflow.identity.entity.User;
import com.owoke.contentflow.identity.entity.UserStatus;
import com.owoke.contentflow.identity.exception.AccountDisabledException;
import com.owoke.contentflow.identity.exception.EmailAlreadyExistsException;
import com.owoke.contentflow.identity.exception.InvalidCredentialsException;
import com.owoke.contentflow.identity.exception.InvalidProfileException;
import com.owoke.contentflow.identity.exception.ProfileVersionConflictException;
import com.owoke.contentflow.identity.exception.UserNotFoundException;
import com.owoke.contentflow.identity.mapper.UserMapper;
import com.owoke.contentflow.identity.repository.AuthSessionRepository;
import com.owoke.contentflow.identity.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository users;
    private final AuthSessionRepository sessions;
    private final UserMapper mapper;
    private final PasswordEncoder passwords;
    private final Clock clock;

    @Transactional(readOnly = true)
    public UserResponse getProfile(UUID userId) {
        return mapper.toResponse(activeUser(userId));
    }

    @Transactional
    public UserResponse updateProfile(UUID userId, UpdateProfileRequest request) {
        User user = activeUserForUpdate(userId);
        if (!Objects.equals(user.getVersion(), request.version())) {
            throw new ProfileVersionConflictException();
        }
        requirePassword(user, request.currentPassword());
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        String name = request.displayName().trim();
        if (name.length() < 2 || name.length() > 100) {
            throw new InvalidProfileException("displayName", "Имя должно содержать от 2 до 100 символов");
        }
        if (!email.equals(user.getEmail()) && users.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }
        boolean emailChanged = !email.equals(user.getEmail());
        mapper.updateProfile(email, name, user);
        User saved = users.saveAndFlush(user);
        if (emailChanged) {
            sessions.revokeAllForUser(userId, Instant.now(clock));
        }
        return mapper.toResponse(saved);
    }

    @Transactional
    public void changePassword(UUID userId, ChangePasswordRequest request) {
        User user = activeUserForUpdate(userId);
        requirePassword(user, request.currentPassword());
        user.setPasswordHash(passwords.encode(request.newPassword()));
        users.saveAndFlush(user);
        sessions.revokeAllForUser(userId, Instant.now(clock));
    }

    @Transactional
    public void deleteAccount(UUID userId, DeleteAccountRequest request) {
        User user = activeUserForUpdate(userId);
        requirePassword(user, request.currentPassword());
        user.setStatus(UserStatus.DISABLED);
        users.saveAndFlush(user);
        sessions.revokeAllForUser(userId, Instant.now(clock));
    }

    private User activeUser(UUID userId) {
        User user = users.findById(userId).orElseThrow(UserNotFoundException::new);
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AccountDisabledException();
        }
        return user;
    }

    private void requirePassword(User user, String rawPassword) {
        if (!passwords.matches(rawPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
    }

    private User activeUserForUpdate(UUID userId) {
        User user = users.findForUpdate(userId).orElseThrow(UserNotFoundException::new);
        if (user.getStatus() != UserStatus.ACTIVE) { throw new AccountDisabledException(); }
        return user;
    }
}
