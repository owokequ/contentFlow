package com.owoke.contentflow.identity.security;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.*;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.cors.*;
import jakarta.servlet.DispatcherType;
import com.owoke.contentflow.common.error.ErrorCode;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SecurityErrorWriter errors,
            JwtDecoder decoder, SessionJwtAuthenticationConverter converter, TokenProperties properties)
            throws Exception {
        var paths = PathPatternRequestMatcher.withDefaults();
        var webChanges = new OrRequestMatcher(
                paths.matcher(HttpMethod.POST, "/api/v1/auth/login"),
                paths.matcher(HttpMethod.POST, "/api/v1/auth/refresh"),
                paths.matcher(HttpMethod.POST, "/api/v1/auth/logout"));
        var csrfCookies = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfCookies.setCookieCustomizer(cookie -> cookie.secure(properties.cookieSecure()).sameSite("Lax"));
        AuthenticationEntryPoint entryPoint = (request, response, exception) -> {
            ErrorCode code = ErrorCode.UNAUTHORIZED;
            if (exception instanceof OAuth2AuthenticationException oauth) {
                code = switch (oauth.getError().getErrorCode()) {
                    case "SESSION_REVOKED" -> ErrorCode.SESSION_REVOKED;
                    default -> ErrorCode.ACCESS_TOKEN_INVALID;
                };
            }
            for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
                if (cause instanceof JwtValidationException validation && validation.getErrors().stream()
                        .anyMatch(error -> error.getErrorCode().equals("ACCESS_TOKEN_EXPIRED"))) {
                    code = ErrorCode.ACCESS_TOKEN_EXPIRED;
                }
            }
            response.setHeader("WWW-Authenticate", "Bearer");
            errors.write(request, response, code);
        };
        http.authorizeHttpRequests(auth -> auth
                    .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                    .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login",
                            "/api/v1/auth/refresh", "/api/v1/auth/logout", "/api/v1/auth/api/login",
                            "/api/v1/auth/api/refresh", "/api/v1/auth/api/logout").permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/v1/auth/csrf").permitAll()
                    .anyRequest().authenticated())
                .cors(cors -> cors.configurationSource(corsConfiguration(properties)))
                .csrf(csrf -> csrf.csrfTokenRepository(csrfCookies)
                    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                    .requireCsrfProtectionMatcher(webChanges))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(resource -> resource
                    .jwt(jwt -> jwt.decoder(decoder).jwtAuthenticationConverter(converter))
                    .authenticationEntryPoint(entryPoint)
                    .accessDeniedHandler((request, response, exception) ->
                        errors.write(request, response, ErrorCode.ACCESS_DENIED)))
                .exceptionHandling(handling -> handling.authenticationEntryPoint(entryPoint)
                    .accessDeniedHandler((request, response, exception) -> errors.write(request, response,
                        exception instanceof org.springframework.security.web.csrf.CsrfException
                            ? ErrorCode.CSRF_TOKEN_INVALID : ErrorCode.ACCESS_DENIED)));
        return http.build();
    }

    private CorsConfigurationSource corsConfiguration(TokenProperties properties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(properties.allowedOrigins());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN"));
        config.setExposedHeaders(List.of("X-Trace-Id"));
        config.setAllowCredentials(true);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(IdentityUserDetailsService users,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider provider) {
        return new ProviderManager(provider);
    }

    @Bean
    public Clock clock() { return Clock.systemUTC(); }

    @Bean
    public PasswordEncoder passwordEncoder() {
        PasswordEncoder encoder = new Pbkdf2PasswordEncoder("", 16, 600_000,
                Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
        String encoderId = "pbkdf2-sha256-600k";
        return new DelegatingPasswordEncoder(encoderId, Map.of(encoderId, encoder));
    }
}
