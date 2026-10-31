package ru.mtusi.rbpo.lab4.security;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import ru.mtusi.rbpo.lab4.repository.ArticleRepository;

@Component("accessPolicy")
public class AccessPolicy {

    private final ArticleRepository articleRepository;

    public AccessPolicy(ArticleRepository articleRepository) {
        this.articleRepository = articleRepository;
    }

    public boolean canCreateArticle(Authentication authentication, Long authorId) {
        if (hasEditorRole(authentication)) {
            return true;
        }
        UserPrincipal principal = principal(authentication);
        return principal != null && authorId != null && principal.getId().equals(authorId);
    }

    public boolean canEditArticle(Authentication authentication, Long articleId, Long requestedAuthorId) {
        if (hasEditorRole(authentication)) {
            return true;
        }
        UserPrincipal principal = principal(authentication);
        if (principal == null || articleId == null) {
            return false;
        }
        if (requestedAuthorId != null && !requestedAuthorId.equals(principal.getId())) {
            return false;
        }
        return articleRepository.findAuthorIdById(articleId)
                .map(principal.getId()::equals)
                .orElse(false);
    }

    public boolean canAccessArticle(Authentication authentication, Long articleId) {
        return canEditArticle(authentication, articleId, null);
    }

    private boolean hasEditorRole(Authentication authentication) {
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_EDITOR".equals(authority.getAuthority()));
    }

    private UserPrincipal principal(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof UserPrincipal principal)) {
            return null;
        }
        return principal;
    }
}
