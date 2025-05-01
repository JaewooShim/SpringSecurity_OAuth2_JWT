package com.OAuthDemo.OAuthJWT.jwt;

import com.OAuthDemo.OAuthJWT.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtils {
    private final SecretKey key;

    @Value("${spring.jwt.expireMs}")
    private Long jwtExpire;

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

    public String generateJWT(String username, String role) {
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpire))
                .signWith(key)
                .compact();
    }

    public boolean validateJWT(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            System.err.println(e.getMessage());
        }
        return false;
    }
}
