package ru.mtusi.rbpo.lab4.dto;

import ru.mtusi.rbpo.lab4.model.EditionStatus;

import java.time.LocalDate;
import java.util.List;

public record EditionIssueRequest(LocalDate date, List<Long> articleIds, EditionStatus status) {
}
