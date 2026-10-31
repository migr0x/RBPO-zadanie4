package ru.mtusi.rbpo.lab4.dto;

public record RegistrationResponse(
        Long id,
        String username,
        String displayName,
        String email,
        String role,
        String accountStatus
) {
}
