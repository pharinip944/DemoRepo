package com.example.vulndemo.controller;

import com.example.vulndemo.model.User;
import com.example.vulndemo.repo.RawJpaLoginRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.regex.Pattern;

@RestController
public class VulnerableController {
    @Autowired
    RawJpaLoginRepo repo;

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // FIX: Added input validation to prevent SQL Injection and XSS via username
        if (!Pattern.matches("^[a-zA-Z0-9_]{3,32}$", username)) {
            return "Invalid credentials";
        }
        // FIX: Added input validation to prevent SQL Injection and XSS via password
        if (!Pattern.matches("^[a-zA-Z0-9_!@#$%^&*()\-+=]{3,32}$", password)) {
            return "Invalid credentials";
        }
        User user = repo.findByUsernameAndPassword(username, password);
        if (user != null) {
            // FIX: Escape output to prevent XSS in username
            return "Welcome, " + username.replaceAll("[<>]", "");
        }
        return "Invalid credentials";
    }
}
