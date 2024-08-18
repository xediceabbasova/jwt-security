package com.company.security.auth;

import lombok.Builder;

@Builder
public record AuthenticationResponse(
        String token
) {
}
