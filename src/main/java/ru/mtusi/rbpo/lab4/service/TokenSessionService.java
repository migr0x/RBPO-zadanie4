package ru.mtusi.rbpo.lab4.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mtusi.rbpo.lab4.dto.LoginRequest;
import ru.mtusi.rbpo.lab4.dto.TokenPairResponse;
import ru.mtusi.rbpo.lab4.dto.TokenRegistrationRequest;
import ru.mtusi.rbpo.lab4.exception.RefreshReplayException;
import ru.mtusi.rbpo.lab4.exception.TokenAuthenticationException;
import ru.mtusi.rbpo.lab4.model.AccountStatus;
import ru.mtusi.rbpo.lab4.model.SessionStatus;
import ru.mtusi.rbpo.lab4.model.User;
import ru.mtusi.rbpo.lab4.model.UserSession;
import ru.mtusi.rbpo.lab4.repository.UserRepository;
import ru.mtusi.rbpo.lab4.repository.UserSessionRepository;
import ru.mtusi.rbpo.lab4.security.JwtService;

import java.time.Clock;
import java.time.Instant;

@Service
public class TokenSessionService {

    private final UserRepository users;
    private final UserSessionRepository sessions;
    private final RegistrationService registration;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final Clock clock;

    public TokenSessionService(UserRepository users, UserSessionRepository sessions,
                               RegistrationService registration, PasswordEncoder passwordEncoder,
                               JwtService jwtService, Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.registration = registration;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.clock = clock;
    }

    @Transactional
    public TokenPairResponse login(LoginRequest request) {
        User user = users.findByUsernameIgnoreCase(request.username().trim())
                .orElseThrow(TokenAuthenticationException::new);
        if (user.getAccountStatus() != AccountStatus.ACTIVE
                || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new TokenAuthenticationException();
        }
        return issue(user, request.deviceId());
    }

    @Transactional
    public TokenPairResponse register(TokenRegistrationRequest request) {
        User user = registration.register(request.registrationRequest());
        return issue(user, request.deviceId());
    }

    @Transactional(noRollbackFor = RefreshReplayException.class)
    public TokenPairResponse refresh(String refreshToken) {
        Jwt refresh;
        try {
            refresh = jwtService.validateRefreshToken(refreshToken);
        } catch (JwtException exception) {
            throw new TokenAuthenticationException();
        }
        // The row lock lasts until the service transaction commits: only one exchange wins.
        UserSession previous = sessions.findByRefreshToken(refreshToken)
                .orElseThrow(TokenAuthenticationException::new);
        User user = users.findByUsernameIgnoreCase(previous.getUsername())
                .orElseThrow(TokenAuthenticationException::new);
        if (user.getAccountStatus() != AccountStatus.ACTIVE
                || !user.getUsername().equals(previous.getUsername())
                || !refresh.getSubject().equals(previous.getUsername())
                || !previous.getRefreshTokenExpiry().isAfter(Instant.now(clock))) {
            throw new TokenAuthenticationException();
        }
        if (previous.getStatus() == SessionStatus.USED) {
            previous.setStatus(SessionStatus.REVOKED);
            sessions.saveAndFlush(previous);
            throw new RefreshReplayException();
        }
        if (previous.getStatus() != SessionStatus.ACTIVE) {
            throw new TokenAuthenticationException();
        }
        previous.setStatus(SessionStatus.USED);
        // A new-row failure rolls back both this update and the attempted insert.
        return issue(user, previous.getDeviceId());
    }

    private TokenPairResponse issue(User user, String deviceId) {
        Jwt access = jwtService.createAccessToken(user.getUsername());
        Jwt refresh = jwtService.createRefreshToken(user.getUsername());
        sessions.saveAndFlush(new UserSession(user.getUsername(), deviceId,
                access.getTokenValue(), refresh.getTokenValue(),
                access.getExpiresAt(), refresh.getExpiresAt()));
        return new TokenPairResponse(access.getTokenValue(), refresh.getTokenValue());
    }
}
