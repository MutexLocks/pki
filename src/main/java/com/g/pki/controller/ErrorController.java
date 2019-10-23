package com.g.pki.controller;

import com.g.pki.exceptions.DaoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ErrorController {
    private Logger logger = LoggerFactory.getLogger(getClass());

    @ExceptionHandler(DaoException.class)
    public String daoExceptionHandler(DaoException e) {
        return e.getMessage();
    }
}
