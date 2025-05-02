package com.OAuthDemo.OAuthJWT.oauth2;

import com.OAuthDemo.OAuthJWT.dto.CustomOAuth2User;
import com.OAuthDemo.OAuthJWT.dto.CustomOIDCUser;
import com.OAuthDemo.OAuthJWT.entity.RefreshEntity;
import com.OAuthDemo.OAuthJWT.jwt.JWTUtils;
import com.OAuthDemo.OAuthJWT.repository.RefreshRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Date;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtils jwtUtils;

    @Value("${spring.jwt.access.expireMs}")
    private int jwtAccessExpire;

    @Value("${spring.jwt.refresh.expireMs}")
    private int jwtRefreshExpire;

    private final RefreshRepository refreshRepository;

    public CustomSuccessHandler(JWTUtils jwtUtils, RefreshRepository refreshRepository) {
        this.jwtUtils = jwtUtils;
        this.refreshRepository = refreshRepository;
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
            String access = jwtUtils.generateJWT("access", username, role, jwtAccessExpire);
            String refresh = jwtUtils.generateJWT("refresh", username, role, jwtRefreshExpire);

            // store refresh token in db
            addRefreshEntity(username, refresh);

            response.setHeader("access", access);
            response.addCookie(createCookie("refresh", refresh));
            response.setStatus(HttpStatus.OK.value());
            response.sendRedirect("http://localhost:3000");
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private void addRefreshEntity(String username, String refresh) {
        Date date = new Date(System.currentTimeMillis() + jwtRefreshExpire);

        RefreshEntity refreshEntity = new RefreshEntity(refresh, username, date.toString());
        refreshRepository.save(refreshEntity);
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(jwtRefreshExpire);
//        cookie.setSecure(true); https only
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }
}
