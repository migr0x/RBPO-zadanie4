package ru.mtusi.rbpo.lab4.exception;

public class TokenAuthenticationException extends RuntimeException {
    public TokenAuthenticationException() {
        super("Invalid credentials or token session");
    }
}
