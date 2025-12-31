package com.github.slowlybeen.pqc.service;

import com.github.slowlybeen.pqc.dto.PqcType;
import com.github.slowlybeen.pqc.pool.KeyPool;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.*;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Map;

@Slf4j
@Service
public class PqcCryptoService {

    private final SecureRandom secureRandom = new SecureRandom();
    private final KeyPool keyPool;
    private final MeterRegistry meterRegistry;

    // Metrics
    private final Timer keyGenTimer;
    private final Timer encapTimer;
    private final Timer decapTimer;
    private final Timer signTimer;
    private final Timer verifyTimer;
    private final Counter signSuccessCounter;
    private final Counter signFailCounter;
    private final Counter verifySuccessCounter;
    private final Counter verifyFailCounter;

    public PqcCryptoService(KeyPool keyPool, MeterRegistry meterRegistry) {
        this.keyPool = keyPool;
        this.meterRegistry = meterRegistry;

        // Timer 등록
        this.keyGenTimer = Timer.builder("pqc.operation.duration")
                .tag("operation", "keygen")
                .description("Key generation duration")
                .register(meterRegistry);
        this.encapTimer = Timer.builder("pqc.operation.duration")
                .tag("operation", "encapsulate")
                .register(meterRegistry);
        this.decapTimer = Timer.builder("pqc.operation.duration")
                .tag("operation", "decapsulate")
                .register(meterRegistry);
        this.signTimer = Timer.builder("pqc.operation.duration")
                .tag("operation", "sign")
                .register(meterRegistry);
        this.verifyTimer = Timer.builder("pqc.operation.duration")
                .tag("operation", "verify")
                .register(meterRegistry);

        // Counter 등록
        this.signSuccessCounter = Counter.builder("pqc.sign.result")
                .tag("result", "success")
                .register(meterRegistry);
        this.signFailCounter = Counter.builder("pqc.sign.result")
                .tag("result", "fail")
                .register(meterRegistry);
        this.verifySuccessCounter = Counter.builder("pqc.verify.result")
                .tag("result", "success")
                .register(meterRegistry);
        this.verifyFailCounter = Counter.builder("pqc.verify.result")
                .tag("result", "fail")
                .register(meterRegistry);
    }

    public Map<String, String> generateKeys(PqcType type) {
        return keyGenTimer.record(() -> keyPool.borrowKey(type));
    }

    public Map<String, String> kemEncapsulate(String publicKeyBase64) {
        return encapTimer.record(() -> {
            byte[] pubBytes = Base64.decode(publicKeyBase64);
            MLKEMPublicKeyParameters params = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, pubBytes);

            MLKEMGenerator generator = new MLKEMGenerator(secureRandom);
            SecretWithEncapsulation sec = generator.generateEncapsulated(params);

            return Map.of(
                    "sharedSecret", Base64.toBase64String(sec.getSecret()),
                    "ciphertext", Base64.toBase64String(sec.getEncapsulation())
            );
        });
    }

    public String kemDecapsulate(String privateKeyBase64, String ciphertextBase64) {
        return decapTimer.record(() -> {
            byte[] privBytes = Base64.decode(privateKeyBase64);
            byte[] cipherBytes = Base64.decode(ciphertextBase64);

            MLKEMPrivateKeyParameters params = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, privBytes);
            MLKEMExtractor extractor = new MLKEMExtractor(params);

            byte[] sharedSecret = extractor.extractSecret(cipherBytes);
            return Base64.toBase64String(sharedSecret);
        });
    }

    public String sign(String privateKeyBase64, String message) {
        return signTimer.record(() -> {
            try {
                byte[] privBytes = decodeBase64Safe(privateKeyBase64);
                byte[] msgBytes = message.getBytes();

                MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, privBytes);
                MLDSASigner signer = new MLDSASigner();
                signer.init(true, new ParametersWithRandom(privParams, secureRandom));
                signer.update(msgBytes, 0, msgBytes.length);

                byte[] signature = signer.generateSignature();
                signSuccessCounter.increment();
                return Base64.toBase64String(signature);
            } catch (CryptoException e) {
                signFailCounter.increment();
                throw new RuntimeException(e);
            }
        });
    }

    public boolean verify(String publicKeyBase64, String message, String signatureBase64) {
        return verifyTimer.record(() -> {
            try {
                byte[] pubBytes = decodeBase64Safe(publicKeyBase64);
                byte[] sigBytes = decodeBase64Safe(signatureBase64);
                byte[] msgBytes = message.getBytes();

                MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pubBytes);
                MLDSASigner verifier = new MLDSASigner();
                verifier.init(false, pubParams);
                verifier.update(msgBytes, 0, msgBytes.length);

                boolean result = verifier.verifySignature(sigBytes);
                if (result) {
                    verifySuccessCounter.increment();
                } else {
                    verifyFailCounter.increment();
                }
                return result;
            } catch (Exception e) {
                verifyFailCounter.increment();
                return false;
            }
        });
    }

    private byte[] decodeBase64Safe(String input) {
        if (input == null) return new byte[0];
        String sanitized = input.replaceAll("\\s+", "");
        return Base64.decode(sanitized);
    }
}