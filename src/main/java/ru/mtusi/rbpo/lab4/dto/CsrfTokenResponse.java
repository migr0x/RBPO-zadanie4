package ru.mtusi.rbpo.lab4.dto;

public record CsrfTokenResponse(String headerName, String parameterName, String token) {
}
