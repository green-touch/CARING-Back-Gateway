package com.caring.apigateway_service.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
public class TokenUtil {

    public static String validateJwt(String jwt, List<String> secretKeys) {
        for (String secret : secretKeys) {
            if (secret != null) {
                String subject = parseJwt(jwt, secret);
                if (subject != null) {
                    return subject;
                }
            }
        }

        return null; // Return null if validation fails for all keys
    }

    private static String parseJwt(String jwt, String secretKey) {
        try {
            String subject = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody()
                    .getSubject();

            log.info("Validated subject: {} with secret: {}", subject, secretKey);

            return subject;
        } catch (Exception e) {
            log.warn("JWT validation failed with secret: {}", secretKey, e);
            return null;
        }
    }

    public static String resolveToken(ServerHttpRequest request) {
        return request.getHeaders()
                .get(HttpHeaders.AUTHORIZATION)
                .get(0).replace("Bearer ", "");
    }
}
