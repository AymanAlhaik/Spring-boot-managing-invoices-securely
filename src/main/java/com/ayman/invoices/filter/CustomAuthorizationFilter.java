package com.ayman.invoices.filter;

import com.ayman.invoices.provider.TokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.http.parser.Authorization;
import org.slf4j.Marker;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.ayman.invoices.utils.ExceptionUtils.processError;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.EMPTY;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String[] PUBLIC_ROUTES = {"/users/login", "/users/verify/code", "/users/register"};
    private static final String HTTP_OPTIONS_METHOD = "OPTIONS";
    protected static final String EMAIL_KEY = "email";
    protected static final String TOKEN_KEY = "token";

    private final TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            Map<String, String> values = getRequestValues(request);
            log.error("values are: {}", values.toString());
            String token = getToken(request);
            if (tokenProvider.isTokenValid(values.get(EMAIL_KEY), token)) {
                List<GrantedAuthority> authorities = tokenProvider.getAuthorities(values.get(TOKEN_KEY));
                Authentication auth = tokenProvider.getAuthentication(values.get(EMAIL_KEY), authorities, request);
                SecurityContextHolder.getContext().setAuthentication(auth);
            } else {
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            log.error("Error while processing request", exception);
            processError(request, response, exception);
        }
    }

    private String getToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(AUTHORIZATION)).filter(header -> header.startsWith(TOKEN_PREFIX)).map(token -> token.replace(TOKEN_PREFIX, StringUtils.EMPTY)).get();
    }

    private Map<String, String> getRequestValues(HttpServletRequest request) {
        Map<String, String> emailKey = Map.of(EMAIL_KEY, tokenProvider.getSubject(getToken(request), request), TOKEN_KEY, getToken(request));
        return emailKey;
    }

    //this method invoked before doFilterInternal, so if there is no authorization header
    //we should not invoke doFilterInternal at all, instead of doing that using if-else
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getHeader(AUTHORIZATION) == null || !request.getHeader(AUTHORIZATION).startsWith(TOKEN_PREFIX) || request.getMethod().equalsIgnoreCase(HTTP_OPTIONS_METHOD) || Arrays.asList(PUBLIC_ROUTES).contains(request.getRequestURI());
    }
}
