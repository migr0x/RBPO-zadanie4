package ru.mtusi.rbpo.lab4.dto;

import ru.mtusi.rbpo.lab4.model.ArticleStatus;

public record ArticleRequest(Long sectionId, Long authorId, String title, String text, ArticleStatus status) {
}
