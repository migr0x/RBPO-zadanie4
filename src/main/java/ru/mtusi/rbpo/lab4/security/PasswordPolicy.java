package ru.mtusi.rbpo.lab4.security;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

@Component
public class PasswordPolicy {

    private static final Pattern LOWERCASE = Pattern.compile(".*[a-z].*");
    private static final Pattern UPPERCASE = Pattern.compile(".*[A-Z].*");
    private static final Pattern DIGIT = Pattern.compile(".*[0-9].*");
    private static final Pattern SPECIAL = Pattern.compile(".*[^A-Za-z0-9].*");

    public void validate(String password) {
        if (password == null || password.length() < 12 || password.getBytes(StandardCharsets.UTF_8).length > 72
                || !LOWERCASE.matcher(password).matches()
                || !UPPERCASE.matcher(password).matches()
                || !DIGIT.matcher(password).matches()
                || !SPECIAL.matcher(password).matches()) {
            throw new IllegalArgumentException(
                    "Password must contain 12 to 72 UTF-8 bytes, including lowercase, uppercase, a digit and a special character");
        }
    }
}
