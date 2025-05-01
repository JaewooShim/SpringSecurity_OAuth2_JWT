package com.OAuth2.OAuth2Demo.oauth2;

import org.hibernate.cfg.Environment;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.stereotype.Component;

@Component
public class SocialClientRegistration {

    private final org.springframework.core.env.Environment env;

    public SocialClientRegistration(org.springframework.core.env.Environment env) {
        this.env = env;
    }


    public ClientRegistration naverClientRegistration() {
        return ClientRegistration.withRegistrationId("naver")
                .clientId(env.getProperty("NAVER_CLIENT_ID"))
                .clientSecret(env.getProperty("NAVER_CLIENT_SECRET"))
                .redirectUri("http://localhost:8080/login/oauth2/code/naver")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("name", "email")
                .authorizationUri("https://nid.naver.com/oauth2.0/authorize")
                .tokenUri("https://nid.naver.com/oauth2.0/token")
                .userInfoUri("https://openapi.naver.com/v1/nid/me")
                .userNameAttributeName("response")
                .build();
    }

    public ClientRegistration googleClientRegistration() {
        return ClientRegistration.withRegistrationId("google")
                .clientId(env.getProperty("GOOGLE_CLIENT_ID"))
                .clientSecret(env.getProperty("GOOGLE_CLIENT_SECRET"))
                .redirectUri("http://localhost:8080/login/oauth2/code/google")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("profile", "email", "openid")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .issuerUri("https://accounts.google.com")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();
    }

    public ClientRegistration kakaoClientRegistration() {
        return ClientRegistration.withRegistrationId("kakao")
                .clientId(env.getProperty("KAKAO_CLIENT_ID"))
                .clientSecret(env.getProperty("KAKAO_CLIENT_SECRET"))
                .redirectUri("http://localhost:8080/login/oauth2/code/kakao")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .scope("profile_nickname", "account_email", "openid")
                .authorizationUri("https://kauth.kakao.com/oauth/authorize")
                .tokenUri("https://kauth.kakao.com/oauth/token")
                .jwkSetUri("https://kauth.kakao.com/.well-known/jwks.json")
                .issuerUri("https://kauth.kakao.com")
                .userInfoUri("https://kapi.kakao.com/v2/user/me")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();
    }
}
