package com.examalchemy.dto;

import lombok.Data;
import java.util.Set;

@Data
public class JwtAuthResponse {
    private String token;
    private String tokenType = "Bearer";
    private String id;
    private String username;
    private String email;
    private Set<String> roles;

    public JwtAuthResponse(String token, String id, String username, String email, Set<String> roles) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }
}