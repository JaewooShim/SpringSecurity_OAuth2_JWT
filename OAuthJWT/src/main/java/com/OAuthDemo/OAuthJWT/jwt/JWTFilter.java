package com.OAuthDemo.OAuthJWT.jwt;

import com.OAuthDemo.OAuthJWT.dto.CustomOAuth2User;
import com.OAuthDemo.OAuthJWT.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtils jwtUtils;

    public JWTFilter(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        try {
//            String authorization = null;
//            Cookie[] cookies = request.getCookies();
//
//            for (Cookie cookie : cookies) {
//                System.out.println(cookie.getName());
//
//                if (cookie.getName().equals("Authorization")) {
//                    authorization = cookie.getValue();
//                }
//            }
//
//            String token = authorization;
//            if (!jwtUtils.validateJWT(token)) {
//                System.out.println("Invalid JWT token");
//                filterChain.doFilter(request, response);
//            }
//
//            String username = jwtUtils.extractUsername(token);
//            String role = jwtUtils.extractRole(token);
//
//            UserDTO userDTO = new UserDTO();
//            userDTO.setName(username);
//            userDTO.setRole(role);
//
//            CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);
//            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                    customOAuth2User,
//                    null,
//                    customOAuth2User.getAuthorities()
//            );
//            SecurityContextHolder.getContext().setAuthentication(authToken);
//        } catch (Exception e) {
//            System.err.println(e.getMessage());
//        }
//        filterChain.doFilter(request, response);
        String accessToken = request.getHeader("access");
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            jwtUtils.validateJWT(accessToken);
            String username = jwtUtils.extractUsername(accessToken);
            String role = jwtUtils.extractRole(accessToken);

            UserDTO userDTO = new UserDTO();
            userDTO.setRole(role);
            userDTO.setName(username);

            CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customOAuth2User,
                    null,
                    customOAuth2User.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authToken);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            PrintWriter writer = response.getWriter();
            writer.println(e.getMessage());

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
