package com.caring.apigateway_service.util;

import com.caring.apigateway_service.dto.MemberInfo;
import io.jsonwebtoken.Claims;
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

    public static MemberInfo parseJwt(String jwt, String secretKey) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();
            MemberInfo memberInfo = null;
            if (claims.getSubject() != null) {
                 memberInfo = MemberInfo.builder()
                         .roles(claims.get("auth", String.class))
                         .memberCode(claims.getSubject())
                         .build();
            }
            return memberInfo;
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
