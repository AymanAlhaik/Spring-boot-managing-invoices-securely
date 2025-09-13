package com.ayman.invoices.utils;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.ayman.invoices.domain.HttpResponse;
import com.ayman.invoices.exception.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;

import java.io.OutputStream;

import static java.time.LocalDateTime.now;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Slf4j
public class ExceptionUtils {
    public static void processError(HttpServletRequest req, HttpServletResponse resp, Exception exception) {
        if (exception instanceof ApiException
                || exception instanceof DisabledException
                || exception instanceof LockedException
                || exception instanceof InvalidClaimException
                || exception instanceof BadCredentialsException
                || exception instanceof TokenExpiredException) {
            HttpResponse httpResponse = getHttpResponse(resp, exception.getMessage(), BAD_REQUEST);
            log.error(exception.getMessage(), exception);
            writeResponse(resp, httpResponse);
        }else {
            HttpResponse httpResponse = getHttpResponse(resp,"An error occurred. Please try again." , INTERNAL_SERVER_ERROR);
            writeResponse(resp, httpResponse);
        }
        log.error(exception.getMessage(), exception);
    }

    private static void writeResponse(HttpServletResponse response, HttpResponse httpResponse) {
        OutputStream outputStream;
        try{
            outputStream = response.getOutputStream();
            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(outputStream, httpResponse);
            outputStream.flush();
        }catch (Exception e) {
            log.error(e.getMessage(), e);
            e.printStackTrace();
        }
    }

    private static HttpResponse getHttpResponse(HttpServletResponse response, String message, HttpStatus status) {
        HttpResponse httpResponse = HttpResponse.builder()
                .timeStamp(now().toString())
                .reason(message)
                .status(status)
                .statusCode(status.value())
                .build();
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(status.value());
        return httpResponse;
    }
}
