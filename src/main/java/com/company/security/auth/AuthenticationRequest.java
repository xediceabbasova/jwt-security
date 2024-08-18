package com.company.security.auth;

public record AuthenticationRequest(
        String email,
        String password
) {
}
