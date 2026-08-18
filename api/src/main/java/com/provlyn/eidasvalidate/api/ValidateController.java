package com.provlyn.eidasvalidate.api;

import com.provlyn.eidasvalidate.core.TimestampValidationResult;
import com.provlyn.eidasvalidate.core.TimestampValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Objects;

/**
 * Public, unauthenticated validation endpoint.
 *
 * <p>Accepts a timestamp token and, optionally, a digest the caller computed
 * locally — never a document. Nothing received here is stored or logged;
 * request bodies do not appear in application logs, and there is no
 * persistence layer for them to land in even by accident.
 */
@RestController
public class ValidateController {

    private final TimestampValidator validator;

    public ValidateController(TimestampValidator validator) {
        this.validator = Objects.requireNonNull(validator, "validator");
    }

    @PostMapping("/api/v1/validate")
    public TimestampValidationResult validate(@RequestBody ValidateRequest request) {
        if (request == null || isBlank(request.token())) {
            throw new BadRequestException("A base64-encoded token is required.");
        }

        byte[] token = decode(request.token(), "token");

        if (isBlank(request.digest())) {
            return validator.validate(token);
        }

        if (isBlank(request.digestAlgorithm())) {
            throw new BadRequestException("digestAlgorithm is required when digest is supplied.");
        }

        byte[] digest = decode(request.digest(), "digest");
        return validator.validateDigest(token, digest, request.digestAlgorithm());
    }

    private static byte[] decode(String base64, String fieldName) {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(fieldName + " is not valid base64.");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorBody> handleBadRequest(BadRequestException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorBody(e.getMessage()));
    }

    /** Malformed input caught before it reaches the validator, not a validation outcome. */
    static final class BadRequestException extends RuntimeException {
        BadRequestException(String message) {
            super(message);
        }
    }

    record ErrorBody(String error) {
    }
}
