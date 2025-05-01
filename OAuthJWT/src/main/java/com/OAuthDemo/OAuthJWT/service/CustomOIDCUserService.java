package com.OAuthDemo.OAuthJWT.service;

import com.OAuthDemo.OAuthJWT.dto.*;
import com.OAuthDemo.OAuthJWT.entity.UserEntity;
import com.OAuthDemo.OAuthJWT.repository.UserRepository;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Map;

@Service
public class CustomOIDCUserService extends OidcUserService {

    private final UserRepository userRepository;

    public CustomOIDCUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        System.out.println("OIDC");
        System.out.println(oidcUser);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response;

        if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oidcUser.getAttributes());
        } else if (registrationId.equals("kakao")) {
            oAuth2Response = new KakaoResponse(oidcUser.getAttributes());
        } else {
            return oidcUser;
        }
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        UserEntity userEntity = userRepository.findByUsername(username)
                .map(existingUser -> {
                    existingUser.setEmail(oAuth2Response.getEmail());
                    existingUser.setName(oAuth2Response.getName());
                    return existingUser;
                }).orElseGet(() -> {
                            return new UserEntity(username, oAuth2Response.getName(), oAuth2Response.getEmail(), "ROLE_USER");
                        }
                );
        UserDTO userDTO = new UserDTO();
        userDTO.setRole(userEntity.getRole());
        userDTO.setUsername(userEntity.getUsername());
        userDTO.setName(userEntity.getName());
        userRepository.save(userEntity);
        return new CustomOIDCUser(userDTO, oidcUser);
    }
}
