package ru.mtusi.rbpo.lab4.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.mtusi.rbpo.lab4.dto.EditionIssueRequest;
import ru.mtusi.rbpo.lab4.model.EditionIssue;
import ru.mtusi.rbpo.lab4.service.EditionIssueService;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/edition-issues")
public class EditionIssueController {

    private final EditionIssueService service;

    public EditionIssueController(EditionIssueService service) {
        this.service = service;
    }

    @GetMapping
    public List<EditionIssue> findAll() {
        return service.findAll();
    }

    @GetMapping("/{id}")
    public EditionIssue findById(@PathVariable Long id) {
        return service.findById(id);
    }

    @PostMapping
    @PreAuthorize("hasRole('EDITOR')")
    public ResponseEntity<EditionIssue> create(@RequestBody EditionIssueRequest request) {
        EditionIssue created = service.create(request);
        return ResponseEntity.created(URI.create("/api/edition-issues/" + created.getId())).body(created);
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasRole('EDITOR')")
    public EditionIssue update(@PathVariable Long id, @RequestBody EditionIssueRequest request) {
        return service.update(id, request);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('EDITOR')")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
