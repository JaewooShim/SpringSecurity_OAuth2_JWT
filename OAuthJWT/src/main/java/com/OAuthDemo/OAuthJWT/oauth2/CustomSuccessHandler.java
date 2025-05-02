package com.OAuthDemo.OAuthJWT.oauth2;

import com.OAuthDemo.OAuthJWT.dto.CustomOAuth2User;
import com.OAuthDemo.OAuthJWT.dto.CustomOIDCUser;
import com.OAuthDemo.OAuthJWT.jwt.JWTUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtils jwtUtils;

    @Value("${spring.jwt.expireMs}")
    private int jwtExpire;

    public CustomSuccessHandler(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        Object principal = authentication.getPrincipal();
        String username = null;
        String role = null;

        if (principal instanceof CustomOIDCUser customOIDCUser) {
            username = customOIDCUser.getUsername();

            role = customOIDCUser.getAuthorities().iterator().next().getAuthority();
        } else if (principal instanceof  CustomOAuth2User customOAuth2User) {
            username = customOAuth2User.getUserName();

            role = customOAuth2User.getAuthorities().iterator().next().getAuthority();
        }
        try {
            String jwt = jwtUtils.generateJWT(username, role);
            response.addCookie(createCookie(jwt));
            response.sendRedirect("http://localhost:3000/");
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private Cookie createCookie(String value) {
        Cookie cookie = new Cookie("Authorization", value);
        cookie.setMaxAge(jwtExpire);
//        cookie.setSecure(true); https only
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }
}
