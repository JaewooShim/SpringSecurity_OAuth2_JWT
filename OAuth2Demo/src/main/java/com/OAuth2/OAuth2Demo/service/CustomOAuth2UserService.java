package com.OAuth2.OAuth2Demo.service;

import com.OAuth2.OAuth2Demo.dto.CustomOAuth2User;
import com.OAuth2.OAuth2Demo.dto.GoogleResponse;
import com.OAuth2.OAuth2Demo.dto.NaverResponse;
import com.OAuth2.OAuth2Demo.dto.OAuth2Response;
import com.OAuth2.OAuth2Demo.entity.UserEntity;
import com.OAuth2.OAuth2Demo.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
    public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("OAuth2");
        System.out.println(oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response;

        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        String username = oAuth2Response.getUsername();

        UserEntity user = userRepository.findByUsername(username)
                .map(existingUser -> {
                    existingUser.setEmail(oAuth2Response.getEmail());
                    return existingUser;
                }).orElseGet(() -> {
                    return new UserEntity(username, oAuth2Response.getEmail(), "ROLE_USER");
                });
        userRepository.save(user);

        String role = user.getRole();

        return new CustomOAuth2User(oAuth2Response, role);
    }
}
