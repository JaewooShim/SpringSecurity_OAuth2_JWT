package com.OAuthDemo.OAuthJWT.service;

import com.OAuthDemo.OAuthJWT.entity.RefreshEntity;
import com.OAuthDemo.OAuthJWT.jwt.JWTUtils;
import com.OAuthDemo.OAuthJWT.repository.RefreshRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Date;

@Service
public class ReissueService {

    private final JWTUtils jwtUtils;

    private final RefreshRepository refreshRepository;

    @Value("${spring.jwt.access.expireMs}")
    private int accessExpire;

    @Value("${spring.jwt.refresh.expireMs}")
    private int refreshExpire;

    public ReissueService(JWTUtils jwtUtils, RefreshRepository refreshRepository) {
        this.jwtUtils = jwtUtils;
        this.refreshRepository = refreshRepository;
    }


    public ResponseEntity<?> reissueToken(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String refresh = null;
        for (Cookie cookie: cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
                break;
            }
        }

        if (refresh == null) {
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        // validate JWT
        try {
            jwtUtils.validateJWT(refresh);
        } catch (Exception e) {
            return new ResponseEntity<>("Invalid token", HttpStatus.BAD_REQUEST);
        }

        String category = jwtUtils.getCategory(refresh);

        if (!category.equals("refresh")) {
            return new ResponseEntity<>("Invalid token", HttpStatus.BAD_REQUEST);
        }

        // check if the refresh token exists
        if (!refreshRepository.existsByRefreshToken(refresh)) {
            return new ResponseEntity<>("Invalid token", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtils.extractUsername(refresh);
        String role = jwtUtils.extractRole(refresh);

        // generate new Access token
        String newAccess = jwtUtils.generateJWT("access", username, role, accessExpire);
        String newRefresh = jwtUtils.generateJWT("refresh", username, role, refreshExpire);

        // delete the previous refresh token and store the new one
        refreshRepository.deleteByRefreshToken(refresh); // also need to delete expired refresh token
        // how? Redis TTL or mysql -> scheduling
        addRefreshEntity(username, newRefresh);

        // response
        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh));
        return new ResponseEntity<>(HttpStatus.OK);
    }

    private void addRefreshEntity(String username, String refresh) {
        Date date = new Date(System.currentTimeMillis() + refreshExpire);

        RefreshEntity refreshEntity = new RefreshEntity(refresh, username, date.toString());
        refreshRepository.save(refreshEntity);
    }
    public Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(refreshExpire);
//        cookie.setSecure(true);
//        cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }
}
