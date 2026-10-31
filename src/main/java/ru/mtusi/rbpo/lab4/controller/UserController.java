package ru.mtusi.rbpo.lab4.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import jakarta.validation.Valid;
import ru.mtusi.rbpo.lab4.dto.AccountStatusRequest;
import ru.mtusi.rbpo.lab4.dto.PasswordChangeRequest;
import org.springframework.web.bind.annotation.*;
import ru.mtusi.rbpo.lab4.dto.UserRequest;
import ru.mtusi.rbpo.lab4.model.User;
import ru.mtusi.rbpo.lab4.service.UserService;

import java.net.URI;
import java.util.List;

@RestController
@PreAuthorize("hasRole('EDITOR')")
@RequestMapping("/api/users")
public class UserController {

    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @GetMapping
    public List<User> findAll() {
        return service.findAll();
    }

    @GetMapping("/{id}")
    public User findById(@PathVariable Long id) {
        return service.findById(id);
    }

    @PostMapping
    public ResponseEntity<User> create(@RequestBody UserRequest request) {
        User created = service.create(request);
        return ResponseEntity.created(URI.create("/api/users/" + created.getId())).body(created);
    }

    @PatchMapping("/{id}")
    public User update(@PathVariable Long id, @RequestBody UserRequest request) {
        return service.update(id, request);
    }

    @PatchMapping("/{id}/password")
    public User changePassword(@PathVariable Long id, @Valid @RequestBody PasswordChangeRequest request) {
        return service.changePassword(id, request.password());
    }

    @PatchMapping("/{id}/account-status")
    public User updateAccountStatus(@PathVariable Long id, @Valid @RequestBody AccountStatusRequest request) {
        return service.updateAccountStatus(id, request.accountStatus());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
