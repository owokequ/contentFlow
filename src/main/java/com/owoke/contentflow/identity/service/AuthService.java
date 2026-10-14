package com.owoke.contentflow.identity.service;

import java.util.Locale;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.owoke.contentflow.identity.dto.request.RegisterRequest;
import com.owoke.contentflow.identity.dto.response.RegisterResponse;
import com.owoke.contentflow.identity.entity.User;
import com.owoke.contentflow.identity.exception.EmailAlreadyExistsException;
import com.owoke.contentflow.identity.exception.InvalidProfileException;
import com.owoke.contentflow.identity.mapper.UserMapper;
import com.owoke.contentflow.identity.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    @Transactional
    public RegisterResponse userRegister(RegisterRequest dto) {
        String email = dto.email().trim().toLowerCase(Locale.ROOT);
        String displayName = dto.displayName().trim();
        if (displayName.length() < 2 || displayName.length() > 100) {
            throw new InvalidProfileException("displayName",
                    "Имя должно содержать от 2 до 100 символов");
        }
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }

        String passwordHash = passwordEncoder.encode(dto.password());
        User user = userMapper.toUser(email, passwordHash, displayName);
        User savedUser = userRepository.saveAndFlush(user);
        return userMapper.toRegisterResponse(savedUser);
    }
}
