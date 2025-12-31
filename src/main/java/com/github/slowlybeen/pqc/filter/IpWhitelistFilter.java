package com.github.slowlybeen.pqc.filter;

import com.github.slowlybeen.pqc.config.SecurityProperties;
import com.github.slowlybeen.pqc.exception.IpFilterException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

@Slf4j
@Component
public class IpWhitelistFilter extends OncePerRequestFilter {

    private final List<String> allowedIps;
    private final HandlerExceptionResolver exceptionResolver;

    public IpWhitelistFilter(
            SecurityProperties securityProperties, // 설정 클래스 주입
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        this.allowedIps = securityProperties.getAllowedIps(); // List 가져오기
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String clientIp = extractClientIp(request);

            if (isAllowed(clientIp)) {
                log.debug("[IP Filter] 허용: {}", clientIp);

                var auth = new UsernamePasswordAuthenticationToken(
                        clientIp, null, List.of(new SimpleGrantedAuthority("ROLE_INTERNAL")));
                SecurityContextHolder.getContext().setAuthentication(auth);

                filterChain.doFilter(request, response);
            } else {
                log.warn("[IP Filter] 차단: {}", clientIp);
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("{\"error\":\"Access denied\",\"ip\":\"" + clientIp + "\"}");
            }
        } catch (IpFilterException e) {
            // GlobalExceptionHandler로 위임
            exceptionResolver.resolveException(request, response, null, e);
        }
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private boolean isAllowed(String clientIp) {
        for (String allowed : allowedIps) {
            if (allowed.contains("/")) {
                if (isInCidrRange(clientIp, allowed)) return true;
            } else {
                if (allowed.equals(clientIp)) return true;
            }
        }
        return false;
    }

    private boolean isInCidrRange(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/");
            String networkAddress = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);

            InetAddress clientAddr = InetAddress.getByName(ip);
            InetAddress networkAddr = InetAddress.getByName(networkAddress);

            byte[] clientBytes = clientAddr.getAddress();
            byte[] networkBytes = networkAddr.getAddress();

            if (clientBytes.length != networkBytes.length) return false;

            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (clientBytes[i] != networkBytes[i]) return false;
            }

            if (remainingBits > 0 && fullBytes < clientBytes.length) {
                int mask = 0xFF << (8 - remainingBits);
                if ((clientBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) {
                    return false;
                }
            }
            return true;
        } catch (UnknownHostException e) {
            throw new IpFilterException("CIDR 파싱 오류: " + cidr, e);
        }
    }
}