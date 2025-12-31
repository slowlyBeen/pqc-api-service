package com.github.slowlybeen.pqc.aspect;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@Aspect
@Component
public class AuditLogAspect {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    @Around("execution(* com.github.slowlybeen.pqc.controller.*.*(..))")
    public Object audit(ProceedingJoinPoint pjp) throws Throwable {
        String method = pjp.getSignature().getName();
        String clientIp = extractClientIp();
        String timestamp = LocalDateTime.now().format(FORMATTER);
        long start = System.currentTimeMillis();

        try {
            Object result = pjp.proceed();
            long duration = System.currentTimeMillis() - start;

            log.info("[AUDIT] timestamp={} | ip={} | method={} | status=SUCCESS | duration={}ms",
                    timestamp, clientIp, method, duration);

            return result;
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - start;

            log.warn("[AUDIT] timestamp={} | ip={} | method={} | status=FAIL | duration={}ms | error={}",
                    timestamp, clientIp, method, duration, e.getMessage());

            throw e;
        }
    }

    private String extractClientIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isBlank()) {
                    return xForwardedFor.split(",")[0].trim();
                }
                return request.getRemoteAddr();
            }
        } catch (Exception e) {
            log.debug("[AUDIT] IP 추출 실패", e);
        }
        return "unknown";
    }
}