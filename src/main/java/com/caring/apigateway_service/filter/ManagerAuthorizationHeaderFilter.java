package com.caring.apigateway_service.filter;

import com.caring.apigateway_service.dto.MemberInfo;
import com.caring.apigateway_service.util.TokenUtil;
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
public class ManagerAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<ManagerAuthorizationHeaderFilter.Config> {

    private final Environment env;

    public ManagerAuthorizationHeaderFilter(Environment environment) {
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
            MemberInfo memberInfo = TokenUtil.parseJwt(jwt, env.getProperty("token.secret-manager"));

            if (memberInfo.getMemberCode() == null) {
                return onError(exchange, "Invalid MANGER JWT token", HttpStatus.UNAUTHORIZED);
            }

            // 새로운 요청에 memberCode를 추가
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("member-code", memberInfo.getMemberCode())
                    .header("roles", memberInfo.getRoles())
                    .build();
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        });
    }

    private static boolean isContainsKey(ServerHttpRequest request) {
        return request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
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
