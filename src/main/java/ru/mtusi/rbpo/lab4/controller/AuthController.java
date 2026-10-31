package ru.mtusi.rbpo.lab4.controller;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.mtusi.rbpo.lab4.dto.AuthenticatedUserResponse;
import ru.mtusi.rbpo.lab4.dto.CsrfTokenResponse;
import ru.mtusi.rbpo.lab4.dto.RegistrationRequest;
import ru.mtusi.rbpo.lab4.dto.RegistrationResponse;
import ru.mtusi.rbpo.lab4.model.User;
import ru.mtusi.rbpo.lab4.security.UserPrincipal;
import ru.mtusi.rbpo.lab4.service.RegistrationService;

import java.net.URI;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final RegistrationService registrationService;

    public AuthController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @GetMapping("/csrf")
    public CsrfTokenResponse csrf(@RequestAttribute(name = "_csrf") CsrfToken csrfToken) {
        return new CsrfTokenResponse(csrfToken.getHeaderName(), csrfToken.getParameterName(), csrfToken.getToken());
    }

    @PostMapping("/register")
    public ResponseEntity<RegistrationResponse> register(@Valid @RequestBody RegistrationRequest request) {
        User user = registrationService.register(request);
        RegistrationResponse response = new RegistrationResponse(user.getId(), user.getUsername(),
                user.getDisplayName(), user.getEmail(), user.getRole().name(), user.getAccountStatus().name());
        return ResponseEntity.created(URI.create("/api/users/" + user.getId())).body(response);
    }

    @GetMapping("/me")
    public AuthenticatedUserResponse me(@AuthenticationPrincipal UserPrincipal principal) {
        return new AuthenticatedUserResponse(principal.getId(), principal.getUsername(),
                principal.getDisplayName(), principal.getRoleName(), principal.getAccountStatusName());
    }
}
