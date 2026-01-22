package com.business.busi.exception;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MyBusinessProException.class)
    public ResponseEntity<Object> handleMyBusinessProException(MyBusinessProException ex) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), ex.getErrorCode(), ex.getDetails());
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR); 
    }

    @ExceptionHandler(SQLException.class)
    public ResponseEntity<Object> handleSQLException(SQLException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Database error occurred", "SQL_ERROR", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<Object> handleDataAccessException(DataAccessException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Data access error", "DATA_ACCESS_ERROR", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<Object> handleNullPointerException(NullPointerException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Null pointer encountered", "NULL_POINTER", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Object> handleIllegalArgumentException(IllegalArgumentException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Invalid argument provided", "INVALID_ARGUMENT", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleValidationException(MethodArgumentNotValidException ex) {
        List<String> errorMessages = ex.getBindingResult().getAllErrors().stream()
            .map(ObjectError::getDefaultMessage)
            .collect(Collectors.toList());
        
        ErrorDetails errorDetails = new ErrorDetails("Validation failed", "VALIDATION_ERROR", String.join(", ", errorMessages));
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthenticationException(AuthenticationException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Authentication failed", "AUTH_ERROR", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDeniedException(AccessDeniedException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Access denied", "ACCESS_DENIED", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }
    
    @ExceptionHandler(NoSuchAlgorithmException.class)
    public ResponseEntity<Object> handleNoSuchAlgorithmException(NoSuchAlgorithmException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Cryptographic algorithm not found", "NO_SUCH_ALGORITHM", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGenericException(Exception ex) {
        ErrorDetails errorDetails = new ErrorDetails("An unexpected error occurred", "GENERIC_ERROR", ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    
    public static class ErrorDetails {
        private String message;
        private String errorCode;
        private String details;

        public ErrorDetails(String message, String errorCode, String details) {
            this.message = message;
            this.errorCode = errorCode;
            this.details = details;
        }

        public String getMessage() {
            return message;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public String getDetails() {
            return details;
        }
    }
}