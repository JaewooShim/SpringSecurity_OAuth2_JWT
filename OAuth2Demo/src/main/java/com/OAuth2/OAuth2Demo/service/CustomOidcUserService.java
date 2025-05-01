package com.OAuth2.OAuth2Demo.service;

import com.OAuth2.OAuth2Demo.dto.CustomOIDCUser;
import com.OAuth2.OAuth2Demo.dto.GoogleResponse;
import com.OAuth2.OAuth2Demo.dto.KakaoResponse;
import com.OAuth2.OAuth2Demo.dto.OAuth2Response;
import com.OAuth2.OAuth2Demo.entity.UserEntity;
import com.OAuth2.OAuth2Demo.repository.UserRepository;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
public class CustomOidcUserService extends OidcUserService {

    private final UserRepository userRepository;

    public CustomOidcUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        System.out.println("OIDC");
        System.out.println(oidcUser.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        OAuth2Response oAuth2Response;

        if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oidcUser.getAttributes());
        } else if (registrationId.equals("kakao")) {
            oAuth2Response = new KakaoResponse(oidcUser.getAttributes());
        } else return null;

        String username = oAuth2Response.getUsername();

        UserEntity user = userRepository.findByUsername(username)
                .map(existingUser -> {
                    existingUser.setEmail(oAuth2Response.getEmail());
                    return existingUser;
                }).orElseGet(() -> {
                    return new UserEntity(username, oAuth2Response.getEmail(), "ROLE_USER");
                });
        userRepository.save(user);
        String role =  user.getRole();
        return new CustomOIDCUser(oAuth2Response, oidcUser, role);
    }
}
