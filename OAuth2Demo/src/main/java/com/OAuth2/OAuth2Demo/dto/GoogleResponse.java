package com.OAuth2.OAuth2Demo.dto;

// Google response format
//{
//resultcode=00, message=success, id=123123123, name=개발자유미
//}

import java.util.Map;

public class GoogleResponse implements OAuth2Response {

    private final Map<String, Object> attributes;

    public GoogleResponse(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProvider() {
        return "google";
    }

    @Override
    public String getProviderId() {
        return attributes.get("sub").toString();
    }

    @Override
    public String getEmail() {
        return attributes.get("email").toString();
    }

    @Override
    public String getName() {
        return attributes.get("name").toString();
    }

    @Override
    public String getUsername() {
        return this.getProvider() + " " + this.getProviderId();
    }
}
