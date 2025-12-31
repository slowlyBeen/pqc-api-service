package com.github.slowlybeen.pqc.pool;

import com.github.slowlybeen.pqc.dto.PqcType;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.pqc.crypto.mldsa.*;
import org.bouncycastle.pqc.crypto.mlkem.*;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class KeyPool {

    @Value("${pqc.pool.kem-size:20}")
    private int kemPoolSize;

    @Value("${pqc.pool.dsa-size:20}")
    private int dsaPoolSize;

    private final BlockingQueue<Map<String, String>> kemPool = new LinkedBlockingQueue<>();
    private final BlockingQueue<Map<String, String>> dsaPool = new LinkedBlockingQueue<>();
    private final SecureRandom secureRandom = new SecureRandom();

    @PostConstruct
    public void init() {
        log.info("[KeyPool] 초기화 시작 - KEM: {}, DSA: {}", kemPoolSize, dsaPoolSize);
        refillPools();
        log.info("[KeyPool] 초기화 완료 - KEM: {}, DSA: {}", kemPool.size(), dsaPool.size());
    }

    @Scheduled(fixedDelayString = "${pqc.pool.refill-interval:5000}")
    public void refillPools() {
        while (kemPool.size() < kemPoolSize) {
            kemPool.offer(generateKemKeyPair());
        }
        while (dsaPool.size() < dsaPoolSize) {
            dsaPool.offer(generateDsaKeyPair());
        }
        log.debug("[KeyPool] 보충 완료 - KEM: {}, DSA: {}", kemPool.size(), dsaPool.size());
    }

    /**
     * 풀에서 키 획득 (없으면 즉시 생성)
     */
    public Map<String, String> borrowKey(PqcType type) {
        Map<String, String> key = null;

        if (type == PqcType.ML_KEM_768) {
            key = kemPool.poll();
            if (key == null) {
                log.warn("[KeyPool] KEM 풀 고갈, 즉시 생성");
                key = generateKemKeyPair();
            }
        } else if (type == PqcType.ML_DSA_65) {
            key = dsaPool.poll();
            if (key == null) {
                log.warn("[KeyPool] DSA 풀 고갈, 즉시 생성");
                key = generateDsaKeyPair();
            }
        } else {
            throw new IllegalArgumentException("Unsupported PQC Type: " + type);
        }

        return key;
    }

    /**
     * 풀 상태 조회 (모니터링용)
     */
    public Map<String, Integer> getPoolStatus() {
        return Map.of(
                "kemPoolSize", kemPool.size(),
                "dsaPoolSize", dsaPool.size()
        );
    }

    private Map<String, String> generateKemKeyPair() {
        MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
        gen.init(new MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768));
        var kp = gen.generateKeyPair();

        return Map.of(
                "publicKey", Base64.toBase64String(((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded()),
                "privateKey", Base64.toBase64String(((MLKEMPrivateKeyParameters) kp.getPrivate()).getEncoded())
        );
    }

    private Map<String, String> generateDsaKeyPair() {
        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(secureRandom, MLDSAParameters.ml_dsa_65));
        var kp = gen.generateKeyPair();

        return Map.of(
                "publicKey", Base64.toBase64String(((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded()),
                "privateKey", Base64.toBase64String(((MLDSAPrivateKeyParameters) kp.getPrivate()).getEncoded())
        );
    }
}