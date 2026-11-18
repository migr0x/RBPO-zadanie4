package ru.mtusi.rbpo.lab4.controller;

import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.mtusi.rbpo.lab4.dto.LoginRequest;
import ru.mtusi.rbpo.lab4.dto.RefreshRequest;
import ru.mtusi.rbpo.lab4.dto.TokenPairResponse;
import ru.mtusi.rbpo.lab4.dto.TokenRegistrationRequest;
import ru.mtusi.rbpo.lab4.service.TokenSessionService;

@RestController
@RequestMapping("/auth")
public class TokenAuthController {

    private final TokenSessionService tokens;

    public TokenAuthController(TokenSessionService tokens) {
        this.tokens = tokens;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenPairResponse> login(@Valid @RequestBody LoginRequest request) {
        return pair(HttpStatus.OK, tokens.login(request));
    }

    @PostMapping("/register")
    public ResponseEntity<TokenPairResponse> register(@Valid @RequestBody TokenRegistrationRequest request) {
        return pair(HttpStatus.CREATED, tokens.register(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenPairResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return pair(HttpStatus.OK, tokens.refresh(request.refreshToken()));
    }

    private ResponseEntity<TokenPairResponse> pair(HttpStatus status, TokenPairResponse response) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(response);
    }
}
