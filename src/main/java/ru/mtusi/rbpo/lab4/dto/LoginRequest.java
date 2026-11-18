package ru.mtusi.rbpo.lab4.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank @Size(max = 80) String username,
        @NotBlank @Size(max = 72) String password,
        @Size(max = 255) String deviceId
) {
}
