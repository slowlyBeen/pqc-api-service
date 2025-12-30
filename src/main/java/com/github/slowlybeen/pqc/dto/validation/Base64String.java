package com.github.slowlybeen.pqc.dto.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = Base64Validator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Base64String {
    String message() default "Invalid Base64 format";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}