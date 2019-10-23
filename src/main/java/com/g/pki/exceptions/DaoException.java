package com.g.pki.exceptions;

public class DaoException extends RuntimeException {
    public DaoException() {
        super("database operation error");
    }

    public DaoException(String message) {
        super(message);
    }

    public DaoException(String message, Throwable cause) {
        super(message, cause);
    }
}
