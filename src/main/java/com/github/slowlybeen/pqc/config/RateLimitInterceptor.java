package com.github.slowlybeen.pqc.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    // IP별로 버킷을 관리 (Stateless 서버지만, 최소한의 보호를 위해 메모리에 잠시 저장)
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String clientIp = getClientIp(request);
        Bucket bucket = cache.computeIfAbsent(clientIp, this::createNewBucket);

        // 토큰 1개를 소모. 남은 토큰이 없으면 false 반환
        if (bucket.tryConsume(1)) {
            return true;
        } else {
            log.warn("[DoS Protection] Too many requests from IP: {}", clientIp);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.getWriter().write("Too many PQC requests. Please try again later.");
            return false;
        }
    }

    private Bucket createNewBucket(String key) {
        // 정책: 1초에 20개의 요청만 허용 (PQC 연산 부하 고려)
        Bandwidth limit = Bandwidth.classic(20, Refill.greedy(20, Duration.ofSeconds(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}