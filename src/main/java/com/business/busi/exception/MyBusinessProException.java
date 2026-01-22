package com.business.busi.exception;

public class MyBusinessProException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;

    private String errorCode;  
    private String details;    

  
    public MyBusinessProException(String message) {
        super(message);
    }

    
    public MyBusinessProException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

  
    public MyBusinessProException(String message, String errorCode, String details) {
        super(message);
        this.errorCode = errorCode;
        this.details = details;
    }

    
    public String getErrorCode() {
        return errorCode;
    }

    public String getDetails() {
        return details;
    }
}