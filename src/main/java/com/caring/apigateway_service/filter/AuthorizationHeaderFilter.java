package com.caring.apigateway_service.filter;

import com.caring.apigateway_service.util.TokenUtil;
import io.jsonwebtoken.Jwts;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final Environment env;

    public AuthorizationHeaderFilter(Environment environment) {
        super(Config.class);
        this.env = environment;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if (!isContainsKey(request)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }
            String jwt = TokenUtil.resolveToken(request);
            String memberCode = TokenUtil.validateJwt(jwt, List.of(
                    env.getProperty("token.secret-user"),
                    env.getProperty("token.secret-manager")
            ));
            return chain.filter(exchange);
        });
    }

    private static boolean isContainsKey(ServerHttpRequest request) {
        return request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
    }

    private boolean isJwtValid(String jwt, ServerHttpRequest request) {
        String subject = null;

        // 첫 번째 시크릿 키(user)로 검증
        if (validateWithSecret(jwt, env.getProperty("token.secret-user"), subject)) {
            return true;
        }
        // 두 번째 시크릿 키(manager)로 검증
        if (validateWithSecret(jwt, env.getProperty("token.secret-manager"), subject)) {
            return true;
        }
        request.getAttributes().put("memberCode", subject);
        // 둘 다 실패하면 false 반환
        return false;
    }

    private boolean validateWithSecret(String jwt, String secretKey, String subject) {
        try {
            log.info("Validating with secret: {}", secretKey);
            subject = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody()
                    .getSubject();

            log.info("Validated subject = {}", subject);

            // subject가 비어있으면 실패로 간주
            return subject != null && !subject.isEmpty();
        } catch (Exception exception) {
            log.error("JWT validation failed with secret: {}", secretKey, exception);
            subject = null;
            return false;
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();
    }

    public static class Config{
    }
}
