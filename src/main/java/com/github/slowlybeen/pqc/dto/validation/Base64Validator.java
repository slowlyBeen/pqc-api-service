package com.github.slowlybeen.pqc.dto.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.regex.Pattern;

public class Base64Validator implements ConstraintValidator<Base64String, String> {
    // 표준 Base64 패턴 (A-Z, a-z, 0-9, +, /, =)
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/=]+$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) return true; // @NotNull은 다른 어노테이션이 담당
        // 공백 제거 후 검증하거나, 아예 엄격하게 공백도 허용 안 할 수 있음
        return BASE64_PATTERN.matcher(value).matches();
    }
}