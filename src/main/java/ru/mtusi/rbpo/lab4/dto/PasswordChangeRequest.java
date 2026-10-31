package ru.mtusi.rbpo.lab4.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordChangeRequest(@NotBlank @Size(min = 12, max = 72) String password) {
}
