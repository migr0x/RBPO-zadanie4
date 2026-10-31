package ru.mtusi.rbpo.lab4.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.mtusi.rbpo.lab4.dto.EditorialSectionRequest;
import ru.mtusi.rbpo.lab4.model.EditorialSection;
import ru.mtusi.rbpo.lab4.service.EditorialSectionService;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/editorial-sections")
public class EditorialSectionController {

    private final EditorialSectionService service;

    public EditorialSectionController(EditorialSectionService service) {
        this.service = service;
    }

    @GetMapping
    public List<EditorialSection> findAll() {
        return service.findAll();
    }

    @GetMapping("/{id}")
    public EditorialSection findById(@PathVariable Long id) {
        return service.findById(id);
    }

    @PostMapping
    @PreAuthorize("hasRole('EDITOR')")
    public ResponseEntity<EditorialSection> create(@RequestBody EditorialSectionRequest request) {
        EditorialSection created = service.create(request);
        return ResponseEntity.created(URI.create("/api/editorial-sections/" + created.getId())).body(created);
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasRole('EDITOR')")
    public EditorialSection update(@PathVariable Long id, @RequestBody EditorialSectionRequest request) {
        return service.update(id, request);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('EDITOR')")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
