package com.github.slowlybeen.pqc.service;

import com.github.slowlybeen.pqc.dto.PqcType;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mldsa.*;
import org.bouncycastle.pqc.crypto.mlkem.*;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class PqcCryptoService {

    private final SecureRandom secureRandom = new SecureRandom();

    // --- 1. 키 쌍 생성 (Key Generation) ---
    public Map<String, String> generateKeys(PqcType type) {
        AsymmetricCipherKeyPair kp;

        if (type == PqcType.ML_KEM_768) {
            MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
            gen.init(new MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768));
            kp = gen.generateKeyPair();
            return Map.of(
                    "publicKey", Base64.toBase64String(((MLKEMPublicKeyParameters)kp.getPublic()).getEncoded()),
                    "privateKey", Base64.toBase64String(((MLKEMPrivateKeyParameters)kp.getPrivate()).getEncoded())
            );
        } else if (type == PqcType.ML_DSA_65) {
            MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
            gen.init(new MLDSAKeyGenerationParameters(secureRandom, MLDSAParameters.ml_dsa_65));
            kp = gen.generateKeyPair();
            return Map.of(
                    "publicKey", Base64.toBase64String(((MLDSAPublicKeyParameters)kp.getPublic()).getEncoded()),
                    "privateKey", Base64.toBase64String(((MLDSAPrivateKeyParameters)kp.getPrivate()).getEncoded())
            );
        }
        throw new IllegalArgumentException("Unsupported PQC Type");
    }

    // --- 2. ML-KEM: Encapsulation (공개키 -> 암호문 + 공유키) ---
    public Map<String, String> kemEncapsulate(String publicKeyBase64) {
        byte[] pubBytes = Base64.decode(publicKeyBase64);
        MLKEMPublicKeyParameters params = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, pubBytes);

        MLKEMGenerator generator = new MLKEMGenerator(secureRandom);
        SecretWithEncapsulation sec = generator.generateEncapsulated(params);

        return Map.of(
                "sharedSecret", Base64.toBase64String(sec.getSecret()),
                "ciphertext", Base64.toBase64String(sec.getEncapsulation())
        );
    }

    // --- 3. ML-KEM: Decapsulation (개인키 + 암호문 -> 공유키) ---
    public String kemDecapsulate(String privateKeyBase64, String ciphertextBase64) {
        byte[] privBytes = Base64.decode(privateKeyBase64);
        byte[] cipherBytes = Base64.decode(ciphertextBase64);

        MLKEMPrivateKeyParameters params = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, privBytes);
        MLKEMExtractor extractor = new MLKEMExtractor(params);

        byte[] sharedSecret = extractor.extractSecret(cipherBytes);
        return Base64.toBase64String(sharedSecret);
    }

    // --- 4. ML-DSA: Sign (전자 서명) ---
    // throws CryptoException을 추가하여 Controller로 예외 전파
    public String sign(String privateKeyBase64, String message) throws CryptoException {
        byte[] privBytes = decodeBase64Safe(privateKeyBase64);
        byte[] msgBytes = message.getBytes();

        MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, privBytes);
        MLDSASigner signer = new MLDSASigner();

        // 보안성을 위해 난수(SecureRandom)와 함께 초기화
        signer.init(true, new ParametersWithRandom(privParams, secureRandom));

        // 데이터 업데이트 (스트림 방식)
        signer.update(msgBytes, 0, msgBytes.length);

        // 서명 생성
        byte[] signature = signer.generateSignature();

        return Base64.toBase64String(signature);
    }

    // --- 5. ML-DSA: Verify (서명 검증) ---
    public boolean verify(String publicKeyBase64, String message, String signatureBase64) {
        try {
            byte[] pubBytes = decodeBase64Safe(publicKeyBase64);
            byte[] sigBytes = decodeBase64Safe(signatureBase64);
            byte[] msgBytes = message.getBytes();

            MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pubBytes);
            MLDSASigner verifier = new MLDSASigner();

            verifier.init(false, pubParams);
            verifier.update(msgBytes, 0, msgBytes.length); // 검증할 원본 데이터 주입

            return verifier.verifySignature(sigBytes);
        } catch (Exception e) {
            // 서명 형식이 깨졌거나 검증 실패 시 false 반환 (예외를 던지지 않음)
            return false;
        }
    }

    // 안전한 Base64 디코딩 (공백, 개행 제거)
    private byte[] decodeBase64Safe(String input) {
        if (input == null) return new byte[0];
        // 개행문자(\r, \n)나 공백이 섞여있으면 제거 (URL Safe 대응도 고려 가능)
        String sanitized = input.replaceAll("\\s+", "");
        return Base64.decode(sanitized);
    }
}