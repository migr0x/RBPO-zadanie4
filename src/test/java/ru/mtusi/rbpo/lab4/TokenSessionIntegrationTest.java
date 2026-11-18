package ru.mtusi.rbpo.lab4;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import ru.mtusi.rbpo.lab4.model.AccountStatus;
import ru.mtusi.rbpo.lab4.model.SessionStatus;
import ru.mtusi.rbpo.lab4.model.User;
import ru.mtusi.rbpo.lab4.model.UserRole;
import ru.mtusi.rbpo.lab4.model.UserSession;
import ru.mtusi.rbpo.lab4.repository.UserRepository;
import ru.mtusi.rbpo.lab4.repository.UserSessionRepository;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TokenSessionIntegrationTest {

    private static final String PASSWORD = "TokenPassword!2026";
    private static final String TEST_SECRET = "test-only-jwt-secret-with-at-least-32-bytes-2026";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoSpyBean
    private UserSessionRepository sessionRepository;

    private User user;
    private String username;

    @BeforeEach
    void createAccount() {
        username = "jwt_" + UUID.randomUUID().toString().replace("-", "");
        user = userRepository.saveAndFlush(new User(username, "JWT Reporter",
                username + "@example.test", passwordEncoder.encode(PASSWORD),
                UserRole.JOURNALIST, AccountStatus.ACTIVE));
    }

    @Test
    void canonicalRefreshScenarioPreservesHistoryAndCommitsReplayRevocation() throws Exception {
        JsonNode first = login("test-device");
        UserSession original = onlySession();
        assertThat(original.getStatus()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(original.getUsername()).isEqualTo(username);
        assertThat(original.getDeviceId()).isEqualTo("test-device");
        assertThat(original.getAccessToken()).isEqualTo(first.path("accessToken").asText());
        assertThat(original.getRefreshToken()).isEqualTo(first.path("refreshToken").asText());
        assertExpiryMatchesJwt(original);

        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(first)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));

        JsonNode second = successfulPair(mockMvc.perform(post("/auth/refresh")
                .header("Authorization", "Bearer malformed.access.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", first.path("refreshToken").asText()))))
                .andReturn(), 200);
        assertThat(second.path("accessToken").asText()).isNotEqualTo(first.path("accessToken").asText());
        assertThat(second.path("refreshToken").asText()).isNotEqualTo(first.path("refreshToken").asText());
        List<UserSession> afterRotation = sessions();
        assertThat(afterRotation).hasSize(2);
        assertThat(sessionById(original)).satisfies(old -> assertThat(old.getStatus()).isEqualTo(SessionStatus.USED));
        UserSession active = afterRotation.stream().filter(row -> row.getStatus() == SessionStatus.ACTIVE)
                .findFirst().orElseThrow();
        assertThat(active.getDeviceId()).isEqualTo("test-device");
        assertExpiryMatchesJwt(active);

        assertRefused(refresh(first.path("refreshToken").asText()), 401);
        assertThat(sessionById(original).getStatus()).isEqualTo(SessionStatus.REVOKED);
        assertThat(sessions()).hasSize(2);
        assertRefused(refresh(first.path("refreshToken").asText()), 401);
        assertThat(sessions()).hasSize(2);
        assertThat(sessionById(active).getStatus()).isEqualTo(SessionStatus.ACTIVE);
        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(second)))
                .andExpect(status().isOk());
    }

    @Test
    void tokenTypesCannotBeSubstitutedAndInvalidSignatureIsRefused() throws Exception {
        JsonNode pair = login(null);
        String refreshToken = pair.path("refreshToken").asText();
        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + refreshToken))
                .andExpect(status().isUnauthorized());
        assertRefused(refresh(pair.path("accessToken").asText()), 401);
        String[] parts = refreshToken.split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        assertRefused(refresh(String.join(".", parts)), 401);
        assertThat(onlySession().getStatus()).isEqualTo(SessionStatus.ACTIVE);
    }

    @Test
    void everyIssuanceUsesDistinctJtiForBothTokenTypes() throws Exception {
        JsonNode first = login(null);
        JsonNode second = login(null);
        assertThat(List.of(claims(first.path("accessToken").asText()).path("jti").asText(),
                claims(first.path("refreshToken").asText()).path("jti").asText(),
                claims(second.path("accessToken").asText()).path("jti").asText(),
                claims(second.path("refreshToken").asText()).path("jti").asText()))
                .doesNotHaveDuplicates().allSatisfy(jti -> assertThat(jti).isNotBlank());
        assertThat(sessions()).hasSize(2).allSatisfy(this::assertExpiryMatchesJwt);
    }

    @Test
    void invalidLoginAndRequiredFieldsReturnErrorsWithoutTokens() throws Exception {
        assertRefused(postJson("/auth/login", Map.of("username", username, "password", "wrong")), 401);
        assertRefused(postJson("/auth/login", Map.of("username", "missing_" + username, "password", PASSWORD)), 401);
        assertRefused(postJson("/auth/login", Map.of("username", username)), 400);
        assertRefused(postJson("/auth/login", Map.of("username", " ", "password", PASSWORD)), 400);
        assertRefused(postJson("/auth/login", Map.of("username", username, "password", " ")), 400);
        assertRefused(postJson("/auth/refresh", Map.of()), 400);
        assertRefused(postJson("/auth/refresh", Map.of("refreshToken", " ")), 400);
        assertRefused(refresh("not.a.jwt"), 401);
        assertRefused(mockMvc.perform(post("/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content("{" )).andReturn(), 400);
        assertThat(sessions()).isEmpty();
    }

    @Test
    void correctlySignedUnknownExpiredAndIncompleteJwtAreRefused() throws Exception {
        Instant now = Instant.now();
        JwtClaimsSet.Builder complete = JwtClaimsSet.builder().subject(username).issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(600)).id(UUID.randomUUID().toString()).claim("type", "refresh");
        assertRefused(refresh(sign(complete.build())), 401);
        assertRefused(refresh(sign(JwtClaimsSet.builder().subject(username).issuedAt(now.minusSeconds(120))
                .expiresAt(now.minusSeconds(60)).id(UUID.randomUUID().toString()).claim("type", "refresh").build())), 401);
        assertRefused(refresh(sign(JwtClaimsSet.builder().subject(username).issuedAt(now)
                .id(UUID.randomUUID().toString()).claim("type", "refresh").build())), 401);
        assertRefused(refresh(sign(JwtClaimsSet.builder().subject(username).issuedAt(now)
                .expiresAt(now.plusSeconds(600)).claim("type", "refresh").build())), 401);
        assertRefused(refresh(sign(JwtClaimsSet.builder().subject(username).issuedAt(now)
                .expiresAt(now.plusSeconds(600)).id(UUID.randomUUID().toString()).build())), 401);
        assertRefused(refresh(sign(JwtClaimsSet.builder().issuedAt(now).expiresAt(now.plusSeconds(600))
                .id(UUID.randomUUID().toString()).claim("type", "refresh").build())), 401);
        assertRefused(refresh(sign(JwtClaimsSet.builder().subject(username).expiresAt(now.plusSeconds(600))
                .id(UUID.randomUUID().toString()).claim("type", "refresh").build())), 401);
        assertThat(sessions()).isEmpty();
    }

    @Test
    void expiredAccessCannotReachProtectedEndpoint() throws Exception {
        Instant now = Instant.now();
        String expired = sign(JwtClaimsSet.builder().subject(username).issuedAt(now.minusSeconds(120))
                .expiresAt(now.minusSeconds(60)).id(UUID.randomUUID().toString()).claim("type", "access").build());
        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());
        JsonNode pair = login(null);
        successfulPair(mockMvc.perform(post("/auth/refresh")
                .header("Authorization", "Bearer " + expired)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", pair.path("refreshToken").asText()))))
                .andReturn(), 200);
    }

    @Test
    void expiredPersistedSessionIsRefusedEvenWhenJwtHasNotExpired() throws Exception {
        JsonNode pair = login(null);
        UserSession original = onlySession();
        assertThat(original.getRefreshTokenExpiry()).isAfter(Instant.now());
        jdbcTemplate.update("UPDATE user_sessions SET refresh_token_expiry = ? WHERE id = ?",
                OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(1), original.getId());
        assertRefused(refresh(pair.path("refreshToken").asText()), 401);
        assertThat(sessions()).hasSize(1);
        assertThat(sessionById(original).getStatus()).isEqualTo(SessionStatus.ACTIVE);
    }

    @Test
    void signedSubjectMustMatchPersistedSessionOwner() throws Exception {
        JsonNode pair = login(null);
        UserSession original = onlySession();
        String otherUsername = "owner_" + username;
        userRepository.saveAndFlush(new User(otherUsername, "Other JWT Reporter",
                otherUsername + "@example.test", passwordEncoder.encode(PASSWORD),
                UserRole.JOURNALIST, AccountStatus.ACTIVE));
        jdbcTemplate.update("UPDATE user_sessions SET username = ? WHERE id = ?", otherUsername, original.getId());
        assertRefused(refresh(pair.path("refreshToken").asText()), 401);
        assertThat(sessionById(original).getStatus()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(sessionRepository.findAll()).filteredOn(row -> row.getUsername().equals(otherUsername))
                .singleElement().satisfies(row -> assertThat(row.getId()).isEqualTo(original.getId()));
    }

    @Test
    void bearerAllowsProtectedPostWithoutCsrfAndEnforcesEditorRole() throws Exception {
        JsonNode journalistPair = login(null);
        Map<String, Object> section = Map.of("name", "JWT Section " + username, "publicationAvailable", true);
        mockMvc.perform(post("/api/editorial-sections").header("Authorization", bearer(journalistPair))
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsBytes(section)))
                .andExpect(status().isForbidden());
        user.setRole(UserRole.EDITOR);
        userRepository.saveAndFlush(user);
        JsonNode editorPair = login(null);
        mockMvc.perform(post("/api/editorial-sections").header("Authorization", bearer(editorPair))
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsBytes(section)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value(section.get("name")));
    }

    @Test
    void lockedAndDisabledUsersCannotLoginRefreshOrUseAccess() throws Exception {
        JsonNode pair = login(null);
        for (AccountStatus accountStatus : List.of(AccountStatus.LOCKED, AccountStatus.DISABLED)) {
            user.setAccountStatus(accountStatus);
            userRepository.saveAndFlush(user);
            assertRefused(postJson("/auth/login", Map.of("username", username, "password", PASSWORD)), 401);
            assertRefused(refresh(pair.path("refreshToken").asText()), 401);
            mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(pair)))
                    .andExpect(status().isUnauthorized());
        }
        assertThat(onlySession().getStatus()).isEqualTo(SessionStatus.ACTIVE);
    }

    @Test
    void missingSessionIsRefusedWithoutCreatingAnotherSession() throws Exception {
        JsonNode pair = login(null);
        sessionRepository.deleteAll(sessions());
        assertRefused(refresh(pair.path("refreshToken").asText()), 401);
        assertThat(sessions()).isEmpty();
    }

    @Test
    void deletedUserCannotRefreshOrUseAccess() throws Exception {
        JsonNode pair = login(null);
        userRepository.delete(user);
        userRepository.flush();
        assertRefused(refresh(pair.path("refreshToken").asText()), 401);
        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(pair)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registerIssuesPairPreservesValidationAndCannotElevateRole() throws Exception {
        String registeredName = "new_" + username;
        Map<String, Object> request = registration(registeredName, registeredName + "@example.test", PASSWORD);
        JsonNode pair = successfulPair(postJson("/auth/register", request), 201);
        User registered = userRepository.findByUsernameIgnoreCase(registeredName).orElseThrow();
        assertThat(registered.getRole()).isEqualTo(UserRole.JOURNALIST);
        assertThat(registered.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(passwordEncoder.matches(PASSWORD, registered.getPasswordHash())).isTrue();
        assertThat(sessionRepository.findAll().stream().filter(row -> row.getUsername().equals(registeredName)))
                .singleElement().satisfies(row -> {
                    assertThat(row.getStatus()).isEqualTo(SessionStatus.ACTIVE);
                    assertThat(row.getDeviceId()).isEqualTo("registered-device");
                    assertThat(row.getRefreshToken()).isEqualTo(pair.path("refreshToken").asText());
                });
        assertRefused(postJson("/auth/register", request), 409);
        assertRefused(postJson("/auth/register", registration("other_" + username,
                registeredName.toUpperCase() + "@EXAMPLE.TEST", PASSWORD)), 409);
        assertRefused(postJson("/auth/register", registration("weak_" + username,
                "weak_" + username + "@example.test", "weak")), 400);
        assertRefused(postJson("/auth/register", Map.of("username", "empty_" + username)), 400);
        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(pair)))
                .andExpect(status().isOk());
    }

    @Test
    void failedSessionSaveRollsBackRegistration() throws Exception {
        String registeredName = "rollback_" + username;
        doThrow(new DataAccessResourceFailureException("Simulated session persistence failure"))
                .when(sessionRepository).saveAndFlush(any(UserSession.class));
        assertTechnicalFailure("/auth/register",
                registration(registeredName, registeredName + "@example.test", PASSWORD));
        assertThat(userRepository.findByUsernameIgnoreCase(registeredName)).isEmpty();
        assertThat(sessionRepository.findAll().stream().filter(row -> row.getUsername().equals(registeredName)))
                .isEmpty();
    }

    @Test
    void failedNewSessionSaveRollsBackUsedStatus() throws Exception {
        JsonNode pair = login(null);
        UserSession original = onlySession();
        doThrow(new DataAccessResourceFailureException("Simulated session persistence failure"))
                .when(sessionRepository).saveAndFlush(any(UserSession.class));
        assertTechnicalFailure("/auth/refresh", Map.of("refreshToken", pair.path("refreshToken").asText()));
        assertThat(sessions()).hasSize(1);
        assertThat(sessionById(original).getStatus()).isEqualTo(SessionStatus.ACTIVE);
    }

    @Test
    void simultaneousRefreshesHaveOnlyOneWinnerAndPersistReplayStatus() throws Exception {
        JsonNode pair = login(null);
        UserSession original = onlySession();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Callable<Integer> call = () -> {
                ready.countDown();
                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Refresh start latch timed out");
                }
                MvcResult result = refresh(pair.path("refreshToken").asText());
                if (result.getResponse().getStatus() == 401) {
                    assertRefused(result, 401);
                } else {
                    successfulPair(result, 200);
                }
                return result.getResponse().getStatus();
            };
            Future<Integer> first = executor.submit(call);
            Future<Integer> second = executor.submit(call);
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            assertThat(List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(200, 401);
        } finally {
            start.countDown();
            executor.shutdownNow();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        }
        assertThat(sessions()).hasSize(2);
        assertThat(sessionById(original).getStatus()).isEqualTo(SessionStatus.REVOKED);
        assertThat(sessions()).filteredOn(row -> row.getStatus() == SessionStatus.ACTIVE).hasSize(1);
    }

    private JsonNode login(String deviceId) throws Exception {
        Map<String, Object> body = deviceId == null
                ? Map.of("username", username, "password", PASSWORD)
                : Map.of("username", username, "password", PASSWORD, "deviceId", deviceId);
        return successfulPair(postJson("/auth/login", body), 200);
    }

    private MvcResult refresh(String refreshToken) throws Exception {
        return postJson("/auth/refresh", Map.of("refreshToken", refreshToken));
    }

    private MvcResult postJson(String path, Object body) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(body))).andReturn();
    }

    private JsonNode successfulPair(MvcResult result, int expectedStatus) throws Exception {
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString())
                .isEqualTo(expectedStatus);
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.size()).isEqualTo(2);
        assertThat(body.path("accessToken").asText()).isNotBlank();
        assertThat(body.path("refreshToken").asText()).isNotBlank();
        assertThat(claims(body.path("accessToken").asText()).path("type").asText()).isEqualTo("access");
        assertThat(claims(body.path("refreshToken").asText()).path("type").asText()).isEqualTo("refresh");
        return body;
    }

    private void assertRefused(MvcResult result, int expectedStatus) throws Exception {
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString())
                .isEqualTo(expectedStatus);
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.has("accessToken")).isFalse();
        assertThat(body.has("refreshToken")).isFalse();
    }

    private void assertTechnicalFailure(String path, Object body) throws Exception {
        try {
            MvcResult result = postJson(path, body);
            assertThat(result.getResponse().getStatus()).isBetween(500, 599);
            assertThat(result.getResponse().getContentAsString()).doesNotContain("accessToken", "refreshToken");
        } catch (jakarta.servlet.ServletException exception) {
            assertThat(exception).hasRootCauseInstanceOf(DataAccessResourceFailureException.class);
        }
    }

    private List<UserSession> sessions() {
        return sessionRepository.findAll().stream().filter(row -> row.getUsername().equals(username)).toList();
    }

    private UserSession onlySession() {
        assertThat(sessions()).hasSize(1);
        return sessions().getFirst();
    }

    private UserSession sessionById(UserSession session) {
        return sessionRepository.findById(session.getId()).orElseThrow();
    }

    private void assertExpiryMatchesJwt(UserSession row) {
        try {
            assertThat(row.getAccessTokenExpiry()).isEqualTo(Instant.ofEpochSecond(claims(row.getAccessToken()).path("exp").asLong()));
            assertThat(row.getRefreshTokenExpiry()).isEqualTo(Instant.ofEpochSecond(claims(row.getRefreshToken()).path("exp").asLong()));
            assertThat(row.getAccessTokenExpiry().getNano()).isZero();
            assertThat(row.getRefreshTokenExpiry().getNano()).isZero();
        } catch (Exception exception) {
            throw new AssertionError("Persisted token is not a valid JWT", exception);
        }
    }

    private JsonNode claims(String jwt) throws Exception {
        return objectMapper.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }

    private String bearer(JsonNode pair) {
        return "Bearer " + pair.path("accessToken").asText();
    }

    private String sign(JwtClaimsSet claims) {
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(TEST_SECRET.getBytes(StandardCharsets.UTF_8)));
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    private Map<String, Object> registration(String registeredName, String email, String password) {
        return Map.of("username", registeredName, "displayName", "Registered JWT Reporter", "email", email,
                "password", password, "deviceId", "registered-device", "role", "EDITOR");
    }
}
