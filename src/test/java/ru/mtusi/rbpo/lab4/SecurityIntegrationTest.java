package ru.mtusi.rbpo.lab4;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import ru.mtusi.rbpo.lab4.model.AccountStatus;
import ru.mtusi.rbpo.lab4.model.Article;
import ru.mtusi.rbpo.lab4.model.ArticleStatus;
import ru.mtusi.rbpo.lab4.model.EditorialSection;
import ru.mtusi.rbpo.lab4.model.User;
import ru.mtusi.rbpo.lab4.model.UserRole;
import ru.mtusi.rbpo.lab4.repository.ArticleRepository;
import ru.mtusi.rbpo.lab4.repository.EditionIssueRepository;
import ru.mtusi.rbpo.lab4.repository.EditorialReviewRepository;
import ru.mtusi.rbpo.lab4.repository.EditorialSectionRepository;
import ru.mtusi.rbpo.lab4.repository.UserRepository;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIntegrationTest {

    private static final String EDITOR_PASSWORD = "EditorPass!2026";
    private static final String JOURNALIST_PASSWORD = "JournalistPass!2026";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EditorialSectionRepository sectionRepository;

    @Autowired
    private ArticleRepository articleRepository;

    @Autowired
    private EditorialReviewRepository reviewRepository;

    @Autowired
    private EditionIssueRepository issueRepository;

    private Long ownArticleId;
    private Long otherArticleId;
    private Long editorId;
    private Long journalistId;
    private Long sectionId;

    @BeforeEach
    void prepareAccountsAndArticles() {
        issueRepository.deleteAll();
        reviewRepository.deleteAll();
        articleRepository.deleteAll();
        sectionRepository.deleteAll();
        userRepository.deleteAll();

        User editor = userRepository.save(new User("security_editor", "Security Editor",
                "security-editor@example.test", passwordEncoder.encode(EDITOR_PASSWORD),
                UserRole.EDITOR, AccountStatus.ACTIVE));
        User journalist = userRepository.save(new User("security_journalist", "Security Journalist",
                "security-journalist@example.test", passwordEncoder.encode(JOURNALIST_PASSWORD),
                UserRole.JOURNALIST, AccountStatus.ACTIVE));
        editorId = editor.getId();
        journalistId = journalist.getId();
        EditorialSection section = sectionRepository.save(new EditorialSection("Security Tests", true));
        sectionId = section.getId();
        Article ownArticle = articleRepository.save(new Article(section, journalist,
                "Own article", "Text written by the journalist", ArticleStatus.DRAFT));
        Article otherArticle = articleRepository.save(new Article(section, editor,
                "Other article", "Text written by the editor", ArticleStatus.DRAFT));
        ownArticleId = ownArticle.getId();
        otherArticleId = otherArticle.getId();
    }

    @Test
    void basicAuthenticationUsesAccountsStoredInDatabase() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("credentials")));

        mockMvc.perform(get("/api/auth/me").with(httpBasic("security_editor", EDITOR_PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("EDITOR"))
                .andExpect(jsonPath("$.accountStatus").value("ACTIVE"));

        mockMvc.perform(get("/api/auth/me").with(httpBasic("security_editor", "wrong-password")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void journalistCanManageOwnArticleButCannotAccessEditorFunctions() throws Exception {
        mockMvc.perform(get("/api/articles/{id}", ownArticleId)
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD)))
                .andExpect(status().isOk());

        mockMvc.perform(patch("/api/articles/{id}", ownArticleId)
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Updated by owner\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Updated by owner"));

        mockMvc.perform(patch("/api/articles/{id}", otherArticleId)
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Unauthorized change\"}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/users").with(httpBasic("security_journalist", JOURNALIST_PASSWORD)))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/business-operations/articles/{id}/approve", ownArticleId)
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"remarks\":\"Not allowed\"}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/business-operations/articles/{id}/submit-for-review", otherArticleId)
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    void journalistCanCreateOnlyArticlesAssignedToTheirOwnAccount() throws Exception {
        mockMvc.perform(post("/api/articles")
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ArticlePayload(
                                sectionId, journalistId, "Own article", "Own text", "DRAFT"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.authorId").value(journalistId));

        mockMvc.perform(post("/api/articles")
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ArticlePayload(
                                sectionId, editorId, "Impersonated article", "Unauthorized text", "DRAFT"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void unsafeRequestsRequireCsrfToken() throws Exception {
        mockMvc.perform(post("/api/business-operations/articles/{id}/submit-for-review", ownArticleId)
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD)))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/business-operations/articles/{id}/submit-for-review", ownArticleId)
                        .with(httpBasic("security_journalist", JOURNALIST_PASSWORD))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_REVIEW"));
    }

    @Test
    void csrfEndpointReturnsTokenThatCanBeUsedForRegistration() throws Exception {
        MvcResult tokenResult = mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.headerName").value("X-CSRF-TOKEN"))
                .andReturn();
        JsonNode tokenJson = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        String csrfToken = tokenJson.get("token").asText();
        MockHttpSession session = (MockHttpSession) tokenResult.getRequest().getSession(false);

        String registrationBody = """
                {"username":"registered_reporter","displayName":"Registered Reporter","email":"registered@example.test","password":"StrongPassword!2026","role":"EDITOR"}
                """;
        mockMvc.perform(post("/api/auth/register")
                        .session(session)
                        .header("X-CSRF-TOKEN", csrfToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("JOURNALIST"))
                .andExpect(jsonPath("$.accountStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        mockMvc.perform(post("/api/auth/register")
                        .session(session)
                        .header("X-CSRF-TOKEN", csrfToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody))
                .andExpect(status().isConflict());

        User registered = userRepository.findByUsernameIgnoreCase("registered_reporter").orElseThrow();
        org.junit.jupiter.api.Assertions.assertTrue(passwordEncoder.matches(
                "StrongPassword!2026", registered.getPasswordHash()));
        org.junit.jupiter.api.Assertions.assertFalse(registered.getPasswordHash().equals("StrongPassword!2026"));
    }

    @Test
    void editorCanProvisionAnAccountWithoutExposingItsPasswordHash() throws Exception {
        User provisioned = userRepository.save(new User("provisioned_reporter", "Provisioned Reporter",
                "provisioned@example.test", passwordEncoder.encode("InitialPassword!2026"),
                UserRole.JOURNALIST, AccountStatus.DISABLED));

        mockMvc.perform(patch("/api/users/{id}/password", provisioned.getId())
                        .with(httpBasic("security_editor", EDITOR_PASSWORD))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"Provisioned!Password2026\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        User updated = userRepository.findById(provisioned.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertTrue(passwordEncoder.matches(
                "Provisioned!Password2026", updated.getPasswordHash()));
        mockMvc.perform(get("/api/auth/me")
                        .with(httpBasic("provisioned_reporter", "Provisioned!Password2026")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("JOURNALIST"));
    }

    @Test
    void weakPasswordsAreRejectedAndAccountStatusIsEnforced() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"weak_reporter\",\"displayName\":\"Weak Reporter\",\"email\":\"weak@example.test\",\"password\":\"weak\"}"))
                .andExpect(status().isBadRequest());

        User journalist = userRepository.findByUsernameIgnoreCase("security_journalist").orElseThrow();
        journalist.setAccountStatus(AccountStatus.LOCKED);
        userRepository.save(journalist);

        mockMvc.perform(get("/api/articles").with(httpBasic("security_journalist", JOURNALIST_PASSWORD)))
                .andExpect(status().isUnauthorized());

        journalist.setAccountStatus(AccountStatus.DISABLED);
        userRepository.save(journalist);

        mockMvc.perform(get("/api/articles").with(httpBasic("security_journalist", JOURNALIST_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    private record ArticlePayload(Long sectionId, Long authorId, String title, String text, String status) {
    }
}
