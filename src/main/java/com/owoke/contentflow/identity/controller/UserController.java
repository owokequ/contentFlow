package com.owoke.contentflow.identity.controller;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.owoke.contentflow.common.error.BusinessException;
import com.owoke.contentflow.common.error.ErrorCode;
import com.owoke.contentflow.identity.dto.request.ChangePasswordRequest;
import com.owoke.contentflow.identity.dto.request.DeleteAccountRequest;
import com.owoke.contentflow.identity.dto.request.UpdateProfileRequest;
import com.owoke.contentflow.identity.dto.response.UserResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import com.owoke.contentflow.identity.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/users/me")
@RequiredArgsConstructor
public class UserController {
    private final UserService users;

    @GetMapping
    public UserResponse get(@AuthenticationPrincipal Jwt principal) {
        return users.getProfile(userId(principal));
    }

    @PutMapping
    public UserResponse update(@AuthenticationPrincipal Jwt principal,
            @RequestBody @Valid UpdateProfileRequest request) {
        return users.updateProfile(userId(principal), request);
    }

    @PutMapping("/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@AuthenticationPrincipal Jwt principal,
            @RequestBody @Valid ChangePasswordRequest request) {
        users.changePassword(userId(principal), request);
    }

    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal Jwt principal,
            @RequestBody @Valid DeleteAccountRequest request) {
        users.deleteAccount(userId(principal), request);
    }

    private UUID userId(Jwt principal) {
        if (principal == null) { throw new BusinessException(ErrorCode.UNAUTHORIZED); }
        return UUID.fromString(principal.getSubject());
    }
}
