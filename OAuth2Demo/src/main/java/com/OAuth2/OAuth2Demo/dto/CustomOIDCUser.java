package com.OAuth2.OAuth2Demo.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class CustomOIDCUser implements OidcUser {

    private final OAuth2Response oAuth2Response;
    private final OidcUser oidcUser;
    private final String role;
    public CustomOIDCUser(OAuth2Response oAuth2Response, OidcUser oidcUser, String role) {
        this.oAuth2Response = oAuth2Response;
        this.oidcUser = oidcUser;
        this.role = role;
    }

    @Override
    public Map<String, Object> getClaims() {
        return oidcUser.getClaims();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return oidcUser.getUserInfo();
    }

    @Override
    public OidcIdToken getIdToken() {
        return oidcUser.getIdToken();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oidcUser.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return role;
            }
        });
    }

    @Override
    public String getName() {
        return oAuth2Response.getName();
    }
}
