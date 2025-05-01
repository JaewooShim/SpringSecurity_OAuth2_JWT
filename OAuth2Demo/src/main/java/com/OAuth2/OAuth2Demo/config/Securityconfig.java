package com.OAuth2.OAuth2Demo.config;

import com.OAuth2.OAuth2Demo.oauth2.CustomClientRegistrationRepo;
import com.OAuth2.OAuth2Demo.service.CustomOAuth2AuthorizedClientService;
import com.OAuth2.OAuth2Demo.service.CustomOAuth2UserService;
import com.OAuth2.OAuth2Demo.service.CustomOidcUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class Securityconfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    private final CustomOidcUserService customOidcUserService;

    private final CustomClientRegistrationRepo customClientRegistrationRepo;

    private final CustomOAuth2AuthorizedClientService customOAuth2AuthorizedClientService;

    private final JdbcTemplate jdbcTemplate;

    public Securityconfig(CustomOAuth2UserService customOAuth2UserService,
                          CustomOidcUserService customOidcUserService, CustomClientRegistrationRepo customClientRegistrationRepo,
                          CustomOAuth2AuthorizedClientService customOAuth2AuthorizedClientService,
                          JdbcTemplate jdbcTemplate) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customOidcUserService = customOidcUserService;
        this.customClientRegistrationRepo = customClientRegistrationRepo;
        this.customOAuth2AuthorizedClientService = customOAuth2AuthorizedClientService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Bean
     SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) ->
                ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests
                        .requestMatchers("/", "/oauth2/**", "/login/**").permitAll()
                        .anyRequest()).authenticated());
        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.csrf(AbstractHttpConfigurer::disable);

        http.oauth2Login(oauth -> oauth
                .loginPage("/login")
                .clientRegistrationRepository(customClientRegistrationRepo.clientRegistrationRepository())
                .authorizedClientService(customOAuth2AuthorizedClientService
                        .oAuth2AuthorizedClientService(jdbcTemplate, customClientRegistrationRepo.clientRegistrationRepository()))
                .userInfoEndpoint(uie -> uie
                    .userService(customOAuth2UserService)
                    .oidcUserService(customOidcUserService)));

        return (SecurityFilterChain)http.build();
    }
}
