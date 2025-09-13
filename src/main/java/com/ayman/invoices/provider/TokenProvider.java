package com.ayman.invoices.provider;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.ayman.invoices.domain.UserPrincipal;
import com.ayman.invoices.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class TokenProvider {
    private final UserService userService;
    private static final String COMPANY_NAME = "Ayman Company";
    private static final String CUSTOMER_MANAGEMENT_SERVICE = "Customer Management Service";

    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 1_800_000;
    //5 days
    private static final long REFRESH_TOKEN_EXPIRATION_TIME = 432_000_000;
    @Value("${JWT.secret}")
    private String secret;

    public String createAccessToken(UserPrincipal userPrincipal) {
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(COMPANY_NAME)
                .withAudience(CUSTOMER_MANAGEMENT_SERVICE)
                .withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
                .withArrayClaim("authorities", claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(secret.getBytes()));

    }
    public String createRefreshToken(UserPrincipal userPrincipal) {
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(COMPANY_NAME)
                .withAudience(CUSTOMER_MANAGEMENT_SERVICE)
                .withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(secret.getBytes()));

    }
    public List<GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return Arrays.stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
    private String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return Objects.requireNonNull(verifier).verify(token).getClaim("authorities").asArray(String.class);
    }

    private JWTVerifier getJWTVerifier() {
        JWTVerifier verifier;
        try{
            Algorithm algorithm = Algorithm.HMAC512(secret.getBytes());
            verifier = JWT.require(algorithm).withIssuer(COMPANY_NAME).build();
        }catch (JWTVerificationException e){
            throw new JWTVerificationException("Token cannot be verified");
        }
        return verifier;
    }
    public Authentication getAuthentication(String email, List<GrantedAuthority> authorities, HttpServletRequest request) {
        //adding the whole userDTO object to the authentication object for making it available a cross the request lifecycle
        UsernamePasswordAuthenticationToken usernamePassAuthToken = new UsernamePasswordAuthenticationToken(userService.getUserByEmail(email), null, authorities);
        usernamePassAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return usernamePassAuthToken;

    }
    public boolean isTokenValid(String email, String token) {
        JWTVerifier verifier = getJWTVerifier();
        return StringUtils.isNotEmpty(email) && !isTokenExpired(verifier, token);
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
       Date expiration = verifier.verify(token).getExpiresAt();
       return expiration.before(new Date());
    }
    public String getSubject(String token, HttpServletRequest request) {
        JWTVerifier verifier = getJWTVerifier();
        try{
            return verifier.verify(token).getSubject();
        }
        catch (TokenExpiredException e){
            request.setAttribute("expireMessage", e.getMessage());
            throw e;
        }
        catch (InvalidClaimException e){
            request.setAttribute("invalideClaim", e.getMessage());
            throw e;
        }
        catch (Exception e){
            throw e;
        }
    }

    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
        return userPrincipal.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray(String[]::new);
    }
}
