package com.company.security.auth;

public record RegisterRequest(
        String firstName,
        String lastName,
        String email,
        String password
) {
}
