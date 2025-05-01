package com.OAuth2.OAuth2Demo.dto;

import java.util.Map;

public class KakaoResponse implements OAuth2Response {
    private final Map<String, Object> attributes;

    public KakaoResponse(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getProviderId() {
        return attributes.get("sub").toString();
    }

    @Override
    public String getEmail() {
        return attributes.get("sub").toString();
    }

    @Override
    public String getName() {
        return attributes.get("nickname").toString();
    }

    @Override
    public String getUsername() {
        return this.getProvider() + " " + this.getProviderId();
    }
}
