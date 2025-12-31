package com.github.slowlybeen.pqc.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Getter
@Setter
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {
    private List<String> allowedIps; // 'allowed-ips'와 매핑됨 (케밥 케이스 -> 카멜 케이스 자동 변환)
}