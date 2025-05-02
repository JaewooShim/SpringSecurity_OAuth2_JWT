package com.OAuthDemo.OAuthJWT.jwt;

import com.OAuthDemo.OAuthJWT.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtils {
    private final SecretKey key;

    public JWTUtils(@Value("${spring.jwt.secret}") String jwtSecret) {
        key = new SecretKeySpec(jwtSecret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String extractUsername(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    public String extractRole(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token)
                .getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token)
                .getPayload().getExpiration().before(new Date());
    }

    public String getCategory(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).
                getPayload().get("category", String.class);
    }
    public String generateJWT(String category, String username, String role, int expireMs) {
        return Jwts.builder()
                .subject(username)
                .claim("category", category)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expireMs))
                .signWith(key)
                .compact();
    }

    public void validateJWT(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
        } catch (MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }
}
