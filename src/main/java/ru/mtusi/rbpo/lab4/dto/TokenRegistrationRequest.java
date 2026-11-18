package ru.mtusi.rbpo.lab4.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record TokenRegistrationRequest(
        @NotBlank @Size(min = 3, max = 80) String username,
        @NotBlank @Size(min = 2, max = 160) String displayName,
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(min = 12, max = 72) String password,
        @Size(max = 255) String deviceId
) {
    public RegistrationRequest registrationRequest() {
        return new RegistrationRequest(username, displayName, email, password);
    }
}
