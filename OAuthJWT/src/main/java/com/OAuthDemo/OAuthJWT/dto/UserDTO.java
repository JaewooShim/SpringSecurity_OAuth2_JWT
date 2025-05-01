package com.OAuthDemo.OAuthJWT.dto;

public class UserDTO {

    private String name;

    private String username;

    private String role;

    public UserDTO(String name, String username, String role) {
        this.name = name;
        this.username = username;
        this.role = role;
    }

    public UserDTO() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
