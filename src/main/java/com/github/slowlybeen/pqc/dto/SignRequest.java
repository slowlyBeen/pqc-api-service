package com.github.slowlybeen.pqc.dto;

import com.github.slowlybeen.pqc.dto.validation.Base64String;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SignRequest {
    @NotBlank
    @Base64String(message = "Private key is required")
    private String privateKeyBase64;

    @NotBlank(message = "Message to sign is required")
    private String message;
}