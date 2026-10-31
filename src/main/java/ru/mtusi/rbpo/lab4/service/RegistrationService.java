package ru.mtusi.rbpo.lab4.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import ru.mtusi.rbpo.lab4.dto.RegistrationRequest;
import ru.mtusi.rbpo.lab4.exception.ResourceConflictException;
import ru.mtusi.rbpo.lab4.model.AccountStatus;
import ru.mtusi.rbpo.lab4.model.User;
import ru.mtusi.rbpo.lab4.model.UserRole;
import ru.mtusi.rbpo.lab4.repository.UserRepository;
import ru.mtusi.rbpo.lab4.security.PasswordPolicy;

@Service
public class RegistrationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;

    public RegistrationService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                               PasswordPolicy passwordPolicy) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
    }

    @Transactional
    public User register(RegistrationRequest request) {
        String username = request.username().trim();
        String displayName = request.displayName().trim();
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        passwordPolicy.validate(request.password());
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new ResourceConflictException("username is already in use");
        }
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new ResourceConflictException("email is already in use");
        }
        String passwordHash = passwordEncoder.encode(request.password());
        return userRepository.save(new User(username, displayName, email,
                passwordHash, UserRole.JOURNALIST, AccountStatus.ACTIVE));
    }

}
