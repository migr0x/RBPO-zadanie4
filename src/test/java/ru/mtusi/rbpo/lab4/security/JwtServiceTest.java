package ru.mtusi.rbpo.lab4.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private static final String SECRET = "test-only-jwt-secret-0123456789-abcdefghijklmnopqrstuvwxyz-0123456789";
    private static final Instant NOW = Instant.parse("2026-11-18T12:34:56.987654321Z");
    private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
    private static final Duration REFRESH_TTL = Duration.ofDays(7);

    private final JwtService service = serviceAt(NOW);

    @Test
    void issuesHs256TokensWithDistinctIdsAndSecondPrecisionExpiry() throws Exception {
        Jwt access = service.createAccessToken("reporter");
        Jwt refresh = service.createRefreshToken("reporter");
        Jwt secondAccess = service.createAccessToken("reporter");
        Jwt secondRefresh = service.createRefreshToken("reporter");

        assertEquals(4, Set.of(access.getId(), refresh.getId(), secondAccess.getId(), secondRefresh.getId()).size());
        assertNotEquals(access.getTokenValue(), secondAccess.getTokenValue());
        assertNotEquals(refresh.getTokenValue(), secondRefresh.getTokenValue());
        assertEquals(NOW.truncatedTo(ChronoUnit.SECONDS), access.getIssuedAt());
        assertEquals(NOW.truncatedTo(ChronoUnit.SECONDS).plus(ACCESS_TTL), access.getExpiresAt());
        assertEquals(NOW.truncatedTo(ChronoUnit.SECONDS).plus(REFRESH_TTL), refresh.getExpiresAt());
        assertEquals(0, refresh.getExpiresAt().getNano());
        assertEquals("access", service.validateAccessToken(access.getTokenValue()).getClaimAsString("type"));
        assertEquals("refresh", service.validateRefreshToken(refresh.getTokenValue()).getClaimAsString("type"));
        assertEquals("reporter", service.validateRefreshToken(refresh.getTokenValue()).getSubject());

        SignedJWT signed = SignedJWT.parse(access.getTokenValue());
        assertEquals(JWSAlgorithm.HS256, signed.getHeader().getAlgorithm());
        assertTrue(signed.verify(new MACVerifier(SECRET.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void accessAndRefreshCannotBeSubstitutedForOneAnother() {
        assertThrows(JwtException.class,
                () -> service.validateRefreshToken(service.createAccessToken("reporter").getTokenValue()));
        assertThrows(JwtException.class,
                () -> service.validateAccessToken(service.createRefreshToken("reporter").getTokenValue()));
    }

    @Test
    void rejectsExpiredTokensIncludingTheExactExpiryBoundaryWithoutClockSkew() {
        Jwt token = service.createRefreshToken("reporter");
        assertThrows(JwtException.class,
                () -> serviceAt(token.getExpiresAt()).validateRefreshToken(token.getTokenValue()));
        assertThrows(JwtException.class,
                () -> serviceAt(token.getExpiresAt().plusSeconds(1)).validateRefreshToken(token.getTokenValue()));
        assertEquals(token.getId(), serviceAt(token.getExpiresAt().minusNanos(1))
                .validateRefreshToken(token.getTokenValue()).getId());
    }

    @Test
    void rejectsTamperedSignatureAndTokensSignedWithAnotherSecret() throws Exception {
        String token = service.createAccessToken("reporter").getTokenValue();
        String[] parts = token.split("\\.");
        char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + parts[1] + "." + replacement + parts[2].substring(1);
        assertThrows(JwtException.class, () -> service.validateAccessToken(tampered));

        String otherKey = "another-test-only-secret-0123456789-abcdefghijklmnopqrstuvwxyz-0123456789";
        assertThrows(JwtException.class,
                () -> service.validateAccessToken(sign(validClaims().build(), JWSAlgorithm.HS256, otherKey)));
    }

    @Test
    void rejectsDifferentAlgorithmsAndUnsignedTokens() throws Exception {
        String hs512 = sign(validClaims().build(), JWSAlgorithm.HS512, SECRET);
        assertThrows(JwtException.class, () -> service.validateAccessToken(hs512));
        String unsigned = new PlainJWT(validClaims().build()).serialize();
        assertThrows(JwtException.class, () -> service.validateAccessToken(unsigned));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sub", "jti", "iat", "exp", "type"})
    void rejectsMissingRequiredClaims(String claim) throws Exception {
        String token = sign(validClaims().claim(claim, null).build());
        assertThrows(JwtException.class, () -> service.validateAccessToken(token));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sub", "jti", "type"})
    void rejectsBlankRequiredStringClaims(String claim) throws Exception {
        String token = sign(validClaims().claim(claim, "  ").build());
        assertThrows(JwtException.class, () -> service.validateAccessToken(token));
    }

    @Test
    void rejectsUnknownOrNonStringTokenType() throws Exception {
        String unknown = sign(validClaims().claim("type", "id").build());
        String numeric = sign(validClaims().claim("type", 42).build());
        assertThrows(JwtException.class, () -> service.validateAccessToken(unknown));
        assertThrows(JwtException.class, () -> service.validateAccessToken(numeric));
    }

    @Test
    void rejectsFutureIssuedAtAndNotBefore() throws Exception {
        String futureIssue = sign(validClaims().issueTime(Date.from(NOW.plusSeconds(10))).build());
        String notYetValid = sign(validClaims().notBeforeTime(Date.from(NOW.plusSeconds(10))).build());
        assertThrows(JwtException.class, () -> service.validateAccessToken(futureIssue));
        assertThrows(JwtException.class, () -> service.validateAccessToken(notYetValid));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"not-a-jwt", "a.b.c", "   "})
    void rejectsMalformedTokensAsJwtExceptions(String token) {
        assertThrows(JwtException.class, () -> service.validateAccessToken(token));
    }

    @Test
    void rejectsWeakSecretsAndUnusableLifetimes() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        assertThrows(IllegalArgumentException.class,
                () -> new JwtService("short", ACCESS_TTL, REFRESH_TTL, clock));
        assertThrows(IllegalArgumentException.class,
                () -> new JwtService(SECRET, Duration.ZERO, REFRESH_TTL, clock));
        assertThrows(IllegalArgumentException.class,
                () -> new JwtService(SECRET, ACCESS_TTL, Duration.ofMillis(999), clock));
    }

    private static JwtService serviceAt(Instant instant) {
        return new JwtService(SECRET, ACCESS_TTL, REFRESH_TTL, Clock.fixed(instant, ZoneOffset.UTC));
    }

    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .subject("reporter")
                .jwtID("test-token-id")
                .issueTime(Date.from(NOW.minusSeconds(1)))
                .expirationTime(Date.from(NOW.plusSeconds(300)))
                .claim("type", "access");
    }

    private static String sign(JWTClaimsSet claims) throws JOSEException {
        return sign(claims, JWSAlgorithm.HS256, SECRET);
    }

    private static String sign(JWTClaimsSet claims, JWSAlgorithm algorithm, String secret) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader(algorithm), claims);
        jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }
}
