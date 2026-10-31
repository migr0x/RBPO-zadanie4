package ru.mtusi.rbpo.lab4.dto;

import ru.mtusi.rbpo.lab4.model.Article;
import ru.mtusi.rbpo.lab4.model.EditorialReview;

public record EditorialDecisionResult(Article article, EditorialReview review) {
}
