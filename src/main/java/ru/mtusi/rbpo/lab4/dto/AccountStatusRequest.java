package ru.mtusi.rbpo.lab4.dto;

import jakarta.validation.constraints.NotNull;
import ru.mtusi.rbpo.lab4.model.AccountStatus;

public record AccountStatusRequest(@NotNull AccountStatus accountStatus) {
}
