package com.OAuthDemo.OAuthJWT.config;

import com.OAuthDemo.OAuthJWT.jwt.CustomLogoutFilter;
import com.OAuthDemo.OAuthJWT.jwt.JWTFilter;
import com.OAuthDemo.OAuthJWT.jwt.JWTUtils;
import com.OAuthDemo.OAuthJWT.oauth2.CustomSuccessHandler;
import com.OAuthDemo.OAuthJWT.repository.RefreshRepository;
import com.OAuthDemo.OAuthJWT.service.CustomOAuth2UserService;
import com.OAuthDemo.OAuthJWT.service.CustomOIDCUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOIDCUserService customOIDCUserService;

    private final CustomSuccessHandler customSuccessHandler;

    private final JWTUtils jwtUtils;

    private final RefreshRepository refreshRepository;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomOIDCUserService customOIDCUserService,
                          CustomSuccessHandler customSuccessHandler, JWTUtils jwtUtils,
                          RefreshRepository refreshRepository) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customOIDCUserService = customOIDCUserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtils = jwtUtils;
        this.refreshRepository = refreshRepository;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.logout().disable();
        http.addFilterBefore(new CustomLogoutFilter(jwtUtils, refreshRepository), LogoutFilter.class);
        http.addFilterBefore(new JWTFilter(jwtUtils), UsernamePasswordAuthenticationFilter.class);

        http.oauth2Login(oauth -> oauth
                .userInfoEndpoint(uie -> uie
                        .userService(customOAuth2UserService)
                        .oidcUserService(customOIDCUserService))
                .successHandler(customSuccessHandler));

        http.authorizeHttpRequests((requests) ->
                (requests
                        .requestMatchers("/", "/login", "/reissue").permitAll()
                        .anyRequest()).authenticated());
        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.cors(httpSecurityCorsConfigurer -> {
            httpSecurityCorsConfigurer.configurationSource(new CorsConfigurationSource() {
                @Override
                public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                    CorsConfiguration configuration = new CorsConfiguration();

                    configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                    configuration.setAllowedMethods(Collections.singletonList("*"));
                    configuration.setAllowCredentials(true);
                    configuration.setAllowedHeaders(Collections.singletonList("*"));
                    configuration.setMaxAge(3600L);

                    configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                    configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                    return configuration;
                }
            });
        });
        return (SecurityFilterChain)http.build();
    }
}
