package com.ayman.invoices.utils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SmsUtils {
    public static final String FROM_NUMBER = "phone number you get from provider";
    public static final String SID_KEY = "api key from provider";
    public static final String TOKEN_KEY = "token from provider";
    public static void sendSms(String phoneNumber, String message) {
        log.info("SMS message sent: {}", message);
    }
}
