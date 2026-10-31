package ru.mtusi.rbpo.lab4.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.mtusi.rbpo.lab4.dto.EditorialDecisionResult;
import ru.mtusi.rbpo.lab4.dto.WorkflowCommandRequest;
import ru.mtusi.rbpo.lab4.model.Article;
import ru.mtusi.rbpo.lab4.model.EditionIssue;
import ru.mtusi.rbpo.lab4.service.EditorialWorkflowService;

@RestController
@RequestMapping("/api/business-operations")
public class BusinessOperationController {

    private final EditorialWorkflowService workflowService;

    public BusinessOperationController(EditorialWorkflowService workflowService) {
        this.workflowService = workflowService;
    }

    @PostMapping("/articles/{articleId}/submit-for-review")
    @PreAuthorize("hasRole('EDITOR') or @accessPolicy.canAccessArticle(authentication, #p0)")
    public Article submitForReview(@PathVariable Long articleId) {
        return workflowService.submitForReview(articleId);
    }

    @PostMapping("/articles/{articleId}/approve")
    @PreAuthorize("hasRole('EDITOR')")
    public EditorialDecisionResult approve(@PathVariable Long articleId,
                                           @RequestBody(required = false) WorkflowCommandRequest request) {
        return workflowService.approveArticle(articleId, request == null ? null : request.remarks());
    }

    @PostMapping("/articles/{articleId}/request-revision")
    @PreAuthorize("hasRole('EDITOR')")
    public EditorialDecisionResult requestRevision(@PathVariable Long articleId,
                                                   @RequestBody(required = false) WorkflowCommandRequest request) {
        return workflowService.requestRevision(articleId, request == null ? null : request.remarks());
    }

    @PostMapping("/issues/{issueId}/articles/{articleId}")
    @PreAuthorize("hasRole('EDITOR')")
    public EditionIssue includeArticle(@PathVariable Long issueId, @PathVariable Long articleId) {
        return workflowService.includeArticle(issueId, articleId);
    }

    @PostMapping("/issues/{issueId}/publish")
    @PreAuthorize("hasRole('EDITOR')")
    public EditionIssue publishIssue(@PathVariable Long issueId) {
        return workflowService.publishIssue(issueId);
    }
}
