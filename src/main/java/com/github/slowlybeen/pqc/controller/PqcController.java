package com.github.slowlybeen.pqc.controller;

import com.github.slowlybeen.pqc.dto.*;
import com.github.slowlybeen.pqc.service.PqcCryptoService;
import org.bouncycastle.crypto.CryptoException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * PQC (양자 내성 암호) Stateless API Controller
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/pqc")
@RequiredArgsConstructor
public class PqcController {

    private final PqcCryptoService pqcService;

    // --- 1. Key Generation ---

    /**
     * 알고리즘별(ML-KEM, ML-DSA) 키 쌍 생성
     */
    @PostMapping("/keys")
    public ResponseEntity<?> generateKeys(@RequestBody @Valid KeyGenRequest request) {
        log.info("[KeyGen] Type: {}", request.getType());
        return ResponseEntity.ok(pqcService.generateKeys(request.getType()));
    }

    // --- 2. Key Exchange (ML-KEM) ---

    /**
     * KEM Encapsulation (공개키 -> 공유키 + 암호문 생성)
     */
    @PostMapping("/kem/encapsulate")
    public ResponseEntity<?> encapsulate(@RequestBody Map<String, String> payload) {
        String pubKey = payload.get("publicKey");
        if(pubKey == null || pubKey.isBlank()) {
            throw new IllegalArgumentException("publicKey missing");
        }

        return ResponseEntity.ok(pqcService.kemEncapsulate(pubKey));
    }

    /**
     * KEM Decapsulation (개인키 + 암호문 -> 공유키 복원)
     */
    @PostMapping("/kem/decapsulate")
    public ResponseEntity<?> decapsulate(@RequestBody Map<String, String> payload) {
        String privKey = payload.get("privateKey");
        String ciphertext = payload.get("ciphertext");

        if(privKey == null || ciphertext == null) {
            throw new IllegalArgumentException("privateKey or ciphertext missing");
        }

        String sharedSecret = pqcService.kemDecapsulate(privKey, ciphertext);
        return ResponseEntity.ok(Map.of("sharedSecret", sharedSecret));
    }

    // --- 3. Digital Signature (ML-DSA) ---

    /**
     * 전자 서명 생성
     * @throws CryptoException 암호화 연산 실패 시 GlobalHandler 처리
     */
    @PostMapping("/dsa/sign")
    public ResponseEntity<?> sign(@RequestBody @Valid SignRequest request) throws CryptoException {
        // 보안: 개인키 및 메시지 본문 로깅 금지
        log.info("[Sign] 요청 수신");

        String signature = pqcService.sign(request.getPrivateKeyBase64(), request.getMessage());
        return ResponseEntity.ok(Map.of("signature", signature));
    }

    /**
     * 전자 서명 유효성 검증
     */
    @PostMapping("/dsa/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> payload) {
        log.info("[Verify] 요청 수신");

        boolean isValid = pqcService.verify(
                payload.get("publicKey"),
                payload.get("message"),
                payload.get("signature")
        );
        return ResponseEntity.ok(Map.of("valid", isValid));
    }
}