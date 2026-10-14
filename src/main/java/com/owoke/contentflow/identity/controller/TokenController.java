package com.owoke.contentflow.identity.controller;

import java.time.Clock;
import java.time.Duration;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import com.owoke.contentflow.identity.dto.request.LoginRequest;
import com.owoke.contentflow.identity.dto.request.LogoutRequest;
import com.owoke.contentflow.identity.dto.request.RefreshRequest;
import com.owoke.contentflow.identity.dto.response.AccessTokenResponse;
import com.owoke.contentflow.identity.dto.response.ApiTokenResponse;
import com.owoke.contentflow.identity.entity.ClientType;
import com.owoke.contentflow.identity.security.TokenProperties;
import com.owoke.contentflow.identity.service.IssuedTokens;
import com.owoke.contentflow.identity.service.TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class TokenController {
    private static final String COOKIE_NAME = "refresh_token";
    private final TokenService tokens;
    private final TokenProperties properties;
    private final Clock clock;

    @PostMapping("/login")
    public ResponseEntity<AccessTokenResponse> webLogin(@RequestBody @Valid LoginRequest request) {
        return web(tokens.login(request, ClientType.WEB));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> webRefresh(
            @CookieValue(name = COOKIE_NAME, required = false) String refreshToken) {
        return web(tokens.refresh(refreshToken, ClientType.WEB));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> webLogout(@CookieValue(name = COOKIE_NAME, required = false) String refreshToken) {
        tokens.logout(refreshToken, ClientType.WEB);
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, cookie("", Duration.ZERO)).build();
    }

    @PostMapping("/api/login")
    public ResponseEntity<ApiTokenResponse> apiLogin(@RequestBody @Valid LoginRequest request) {
        return api(tokens.login(request, ClientType.API));
    }

    @PostMapping("/api/refresh")
    public ResponseEntity<ApiTokenResponse> apiRefresh(@RequestBody @Valid RefreshRequest request) {
        return api(tokens.refresh(request.refreshToken(), ClientType.API));
    }

    @PostMapping("/api/logout")
    public ResponseEntity<Void> apiLogout(@RequestBody(required = false) @Valid LogoutRequest request) {
        tokens.logout(request == null ? null : request.refreshToken(), ClientType.API);
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    private ResponseEntity<ApiTokenResponse> api(IssuedTokens issued) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(issued.apiResponse());
    }

    private ResponseEntity<AccessTokenResponse> web(IssuedTokens issued) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, cookie(issued.refreshToken(),
                        Duration.between(clock.instant(), issued.sessionExpiresAt())))
                .body(issued.webResponse());
    }

    private String cookie(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE_NAME, value).httpOnly(true).secure(properties.cookieSecure())
                .sameSite("Lax").path("/api/v1/auth").maxAge(maxAge.isNegative() ? Duration.ZERO : maxAge)
                .build().toString();
    }
}
