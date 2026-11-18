package ru.mtusi.rbpo.lab4.exception;

/** Only this authentication refusal commits its USED -> REVOKED transition. */
public class RefreshReplayException extends TokenAuthenticationException {
}
