package ru.mtusi.rbpo.lab4.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import ru.mtusi.rbpo.lab4.model.ReviewDecision;

@JsonIgnoreProperties(ignoreUnknown = true)
public record EditorialReviewRequest(Long articleId, ReviewDecision decision, String remarks) {
}
