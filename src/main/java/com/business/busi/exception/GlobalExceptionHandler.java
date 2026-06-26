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
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.business.busi.dto.ErrorDetails;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MyBusinessProException.class)
    public ResponseEntity<ErrorDetails> handleMyBusinessProException(MyBusinessProException ex) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), ex.getErrorCode(), ex.getDetails());
        return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorDetails);
    }

    @ExceptionHandler(SQLException.class)
    public ResponseEntity<ErrorDetails> handleSQLException(SQLException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Database error occurred", "SQL_ERROR", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorDetails);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorDetails> handleDataAccessException(DataAccessException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Data access error", "DATA_ACCESS_ERROR", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorDetails);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<ErrorDetails> handleNullPointerException(NullPointerException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Null pointer encountered", "NULL_POINTER", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorDetails);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorDetails> handleIllegalArgumentException(IllegalArgumentException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Invalid argument provided", "INVALID_ARGUMENT", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(errorDetails);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorDetails> handleValidationException(MethodArgumentNotValidException ex) {
        List<String> errorMessages = ex.getBindingResult().getAllErrors().stream()
            .map(ObjectError::getDefaultMessage)
            .collect(Collectors.toList());
        
        ErrorDetails errorDetails = new ErrorDetails("Validation failed", "VALIDATION_ERROR", String.join(", ", errorMessages));
        return  ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(errorDetails);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorDetails> handleAuthenticationException(AuthenticationException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Authentication failed", "AUTH_ERROR", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(errorDetails);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorDetails> handleAccessDeniedException(AccessDeniedException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Access denied", "ACCESS_DENIED", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(errorDetails);
    }
    
    @ExceptionHandler(NoSuchAlgorithmException.class)
    public ResponseEntity<ErrorDetails> handleNoSuchAlgorithmException(NoSuchAlgorithmException ex) {
        ErrorDetails errorDetails = new ErrorDetails("Cryptographic algorithm not found", "NO_SUCH_ALGORITHM", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorDetails);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDetails> handleGenericException(Exception ex) {
        ErrorDetails errorDetails = new ErrorDetails("An unexpected error occurred", "GENERIC_ERROR", ex.getMessage());
        return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorDetails);
    }

}