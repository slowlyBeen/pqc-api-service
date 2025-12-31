package com.github.slowlybeen.pqc.exception;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.Map;

@RestControllerAdvice
public class PqcGlobalExceptionHandler {

    // 1. PQC 연산 관련 커스텀 예외 처리
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleBadInput(IllegalArgumentException e) {
        return buildErrorResponse(HttpStatus.BAD_REQUEST, "Invalid Key or Parameter Format", e.getMessage());
    }

    // 2. Bouncy Castle 암호화 연산 예외 처리
    @ExceptionHandler({CryptoException.class, DataLengthException.class})
    public ResponseEntity<?> handleCryptoException(Exception e) {
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Cryptography Error", "PQC operation failed: " + e.getMessage());
    }

    // 3. Body가 아예 없거나 JSON 형식이 깨진 경우
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> handleMalformedJson(HttpMessageNotReadableException e) {
        return buildErrorResponse(HttpStatus.BAD_REQUEST, "Malformed JSON Request", "Request body is missing or invalid.");
    }

    // 4. @Valid 검증 실패
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidationError(MethodArgumentNotValidException e) {
        String errorMessage = e.getBindingResult().getFieldError() != null
                ? e.getBindingResult().getFieldError().getDefaultMessage()
                : "Validation error";
        return buildErrorResponse(HttpStatus.BAD_REQUEST, "Validation Error", errorMessage);
    }

    // 5. IP Filter 예외 처리 (신규)
    @ExceptionHandler(IpFilterException.class)
    public ResponseEntity<?> handleIpFilterException(IpFilterException e) {
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "IP Filter Error", e.getMessage());
    }

    // 6. 알 수 없는 내부 서버 오류
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneralException(Exception e) {
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Crypto Error", "Operation failed safely.");
    }

    private ResponseEntity<?> buildErrorResponse(HttpStatus status, String error, String message) {
        return ResponseEntity.status(status).body(Map.of(
                "timestamp", LocalDateTime.now(),
                "status", status.value(),
                "error", error,
                "message", message
        ));
    }
}