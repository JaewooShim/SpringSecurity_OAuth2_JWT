package com.example.SecurityJWT.dto;

import java.util.List;

public record TokenDTO(String username, List<String> role, String jwt) {
}
