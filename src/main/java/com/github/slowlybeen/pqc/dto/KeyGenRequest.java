package com.github.slowlybeen.pqc.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class KeyGenRequest {
    @NotNull(message = "Algorithm type is mandatory")
    private PqcType type;
}