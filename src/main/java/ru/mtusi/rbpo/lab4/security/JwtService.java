package ru.mtusi.rbpo.lab4.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.Map;

@Service
public class JwtService {

    private final NimbusJwtEncoder encoder;
    private final NimbusJwtDecoder decoder;
    private final Duration accessTtl;
    private final Duration refreshTtl;
    private final Clock clock;

    public JwtService(@Value("${security.jwt.secret}") String secret,
                      @Value("${security.jwt.access-ttl}") Duration accessTtl,
                      @Value("${security.jwt.refresh-ttl}") Duration refreshTtl,
                      Clock clock) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("JWT secret must contain at least 32 UTF-8 bytes");
        }
        requireValidTtl(accessTtl);
        requireValidTtl(refreshTtl);
        SecretKey key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        this.encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        this.decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Map.of());
        this.decoder.setClaimSetConverter(claims -> {
            // The default converter synthesizes iat from exp; require the signed claim first.
            if (!(claims.get("sub") instanceof String subject) || subject.isBlank()
                    || !(claims.get("jti") instanceof String id) || id.isBlank()
                    || claims.get("iat") == null || claims.get("exp") == null) {
                throw new JwtException("Required JWT claims are missing or invalid");
            }
            return converter.convert(claims);
        });
        this.decoder.setJwtValidator(this::validateClaims);
        this.accessTtl = accessTtl;
        this.refreshTtl = refreshTtl;
        this.clock = clock;
    }

    public Jwt createAccessToken(String username) {
        return createToken(username, "access", accessTtl);
    }

    public Jwt createRefreshToken(String username) {
        return createToken(username, "refresh", refreshTtl);
    }

    public Jwt validateAccessToken(String token) {
        return validateToken(token, "access");
    }

    public Jwt validateRefreshToken(String token) {
        return validateToken(token, "refresh");
    }

    private Jwt createToken(String username, String type, Duration ttl) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("JWT subject is required");
        }
        Instant issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(username)
                .id(UUID.randomUUID().toString())
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plus(ttl).truncatedTo(ChronoUnit.SECONDS))
                .claim("type", type)
                .build();
        return encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).type("JWT").build(), claims));
    }

    private Jwt validateToken(String token, String expectedType) {
        try {
            Jwt jwt = decoder.decode(token);
            if (!expectedType.equals(jwt.getClaims().get("type"))) {
                throw new JwtException("Invalid JWT type");
            }
            return jwt;
        } catch (IllegalArgumentException exception) {
            throw new JwtException("Invalid JWT", exception);
        }
    }

    private OAuth2TokenValidatorResult validateClaims(Jwt jwt) {
        Instant now = clock.instant();
        Instant issuedAt = jwt.getIssuedAt();
        Instant expiresAt = jwt.getExpiresAt();
        Object subject = jwt.getClaims().get("sub");
        Object tokenId = jwt.getClaims().get("jti");
        Object type = jwt.getClaims().get("type");
        if (!(subject instanceof String value) || value.isBlank()
                || !(tokenId instanceof String id) || id.isBlank()
                || !("access".equals(type) || "refresh".equals(type))
                || issuedAt == null || expiresAt == null
                || issuedAt.isAfter(now) || !expiresAt.isAfter(now)
                || !expiresAt.isAfter(issuedAt)
                || (jwt.getNotBefore() != null && jwt.getNotBefore().isAfter(now))) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token", "JWT claims are missing or invalid", null));
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static void requireValidTtl(Duration ttl) {
        if (ttl == null || ttl.compareTo(Duration.ofSeconds(1)) < 0) {
            throw new IllegalArgumentException("JWT lifetime must be at least one second");
        }
    }
}
