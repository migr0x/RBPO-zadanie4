package ru.mtusi.rbpo.lab4.dto;

public record AuthenticatedUserResponse(
        Long id,
        String username,
        String displayName,
        String role,
        String accountStatus
) {
}
