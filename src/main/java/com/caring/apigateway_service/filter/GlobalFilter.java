package com.caring.apigateway_service.filter;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class GlobalFilter extends AbstractGatewayFilterFactory<GlobalFilter.Config> {
    public GlobalFilter(){
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            logPreFilter(config, request);

            return chain.filter(exchange)
                    .doOnError(throwable -> log.error("Error occurred during request processing: {}", throwable.getMessage(), throwable))
                    .then(Mono.fromRunnable(() -> {
                        ServerHttpResponse response = exchange.getResponse();
                        logPostFilter(config, response);
                    }));
        };
    }

    private void logPreFilter(Config config, ServerHttpRequest request) {
        if (config.isPreLogger()) {
            log.info("Global Filter Pre-Logger: BaseMessage: {}, Request ID: {}", config.getBaseMessage(), request.getId());
        }
    }

    private void logPostFilter(Config config, ServerHttpResponse response) {
        if (config.isPostLogger()) {
            log.info("Global Filter Post-Logger: Response Status Code: {}", response.getStatusCode());
        }
    }

    @Data
    public static class Config {
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }
}
