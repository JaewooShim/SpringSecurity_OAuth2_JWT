package com.OAuthDemo.OAuthJWT.service;

import com.OAuthDemo.OAuthJWT.dto.CustomOAuth2User;
import com.OAuthDemo.OAuthJWT.dto.NaverResponse;
import com.OAuthDemo.OAuthJWT.dto.OAuth2Response;
import com.OAuthDemo.OAuthJWT.dto.UserDTO;
import com.OAuthDemo.OAuthJWT.entity.UserEntity;
import com.OAuthDemo.OAuthJWT.repository.UserRepository;
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
        System.out.println("OAUTH");
        System.out.println(oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        System.out.println(registrationId);

        OAuth2Response oAuth2Response;
        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else return null;
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();

        UserEntity userEntity = userRepository.findByUsername(username)
                .map(existingUser -> {
                    existingUser.setEmail(oAuth2Response.getEmail());
                    existingUser.setName(oAuth2User.getName());
                    return existingUser;
                }).orElseGet(() -> {
                    return new UserEntity(username, oAuth2User.getName(), oAuth2Response.getEmail(), "ROLE_USER");
                        }
                );

        UserDTO userDTO = new UserDTO();
        userDTO.setRole(userEntity.getRole());
        userDTO.setUsername(userEntity.getUsername());
        userDTO.setName(userEntity.getName());
        userRepository.save(userEntity);
        return new CustomOAuth2User(userDTO);
    }
}
