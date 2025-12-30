package com.github.slowlybeen.pqc.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Slf4j
@Configuration
public class PqcProviderConfig {

    @PostConstruct
    public void init() {
        // 기존에 등록된 BC가 있다면 제거하고 가장 최신 버전(LTS)으로 재등록
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        log.info("Quantum-Safe Security Provider Registered: BouncyCastleProvider");
    }
}