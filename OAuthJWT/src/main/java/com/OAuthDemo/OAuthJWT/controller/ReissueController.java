package com.OAuthDemo.OAuthJWT.controller;

import com.OAuthDemo.OAuthJWT.jwt.JWTUtils;
import com.OAuthDemo.OAuthJWT.repository.RefreshRepository;
import com.OAuthDemo.OAuthJWT.service.ReissueService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReissueController {

    private final JWTUtils jwtUtils;

    private final ReissueService reissueService;

    private final RefreshRepository refreshRepository;

    public ReissueController(JWTUtils jwtUtils,
                             ReissueService reissueService, RefreshRepository refreshRepository) {
        this.jwtUtils = jwtUtils;
        this.reissueService = reissueService;
        this.refreshRepository = refreshRepository;
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        return reissueService.reissueToken(request, response);
    }
}
