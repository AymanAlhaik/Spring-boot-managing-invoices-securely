package com.ayman.invoices.repository.implementation;

import com.ayman.invoices.domain.Role;
import com.ayman.invoices.domain.User;
import com.ayman.invoices.domain.UserPrincipal;
import com.ayman.invoices.dto.UserDTO;
import com.ayman.invoices.enumeration.RoleType;
import com.ayman.invoices.enumeration.VerificationType;
import com.ayman.invoices.exception.ApiException;
import com.ayman.invoices.repository.RoleRepository;
import com.ayman.invoices.repository.UserRepository;
import com.ayman.invoices.rowmapper.UserRowMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.*;

import static com.ayman.invoices.enumeration.RoleType.*;
import static com.ayman.invoices.enumeration.VerificationType.ACCOUNT;
import static com.ayman.invoices.query.UserQuery.*;
import static com.ayman.invoices.utils.SmsUtils.sendSms;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.time.DateFormatUtils.format;
import static org.apache.commons.lang3.time.DateUtils.addDays;


@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl implements UserRepository<User>, UserDetailsService {
    //standard SQL date format
    private static final String DATE_FORMAT = "yyyy-MM-dd hh:mm:ss";
    private final NamedParameterJdbcTemplate jdbc;
    private final RoleRepository<Role> roleRepository;
    private final PasswordEncoder encoder;

    @Override
    public User create(User user) {
        //check the email is unique
        if (getEmailCount(user.getEmail().trim().toLowerCase()) > 0) {
            throw new ApiException("Email already in use. Please use a different email and try again.");
        }
        //save new user
        try {
            //storing generated user id
            KeyHolder keyHolder = new GeneratedKeyHolder();
            SqlParameterSource parameters = getSqlParametersSource(user);
            jdbc.update(INSERT_USER_QUERY, parameters, keyHolder);
            user.setId(Objects.requireNonNull(keyHolder.getKey()).longValue());
            //add role to the user
            roleRepository.addRoleToUser(user.getId(), ROLE_USER.name());
            //send verification url
            String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), ACCOUNT.getType());
            //save url in verification table
            jdbc.update(INSERT_ACCOUNT_VERIFICATION_URL_QUERY,
                    Map.of("userId", user.getId(), "url", verificationUrl));
            //send email to user with verification url
//            emailService.sendVerificationUrl(user.getFirstName(), user.getEmail(), verificationUrl, ACCOUNT);
            user.setEnabled(true);
            user.setNotLocked(true);
            //return newly created user
            return user;
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred while creating user. Please try again later.");
        }
    }
    //video 11

    private SqlParameterSource getSqlParametersSource(User user) {
        return new MapSqlParameterSource()
                .addValue("firstName", user.getFirstName())
                .addValue("lastName", user.getLastName())
                .addValue("email", user.getEmail())
                .addValue("password", encoder.encode(user.getPassword()));
    }

    private String getVerificationUrl(String key, String type) {
        return ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/user/verify/" + type + "/" + key).toUriString();
    }

    @Override
    public Collection list(int page, int pageSize) {
        return List.of();
    }

    @Override
    public User get(Long id) {
        return null;
    }

    @Override
    public User update(User data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
    }

    private Integer getEmailCount(String email) {
        return jdbc.queryForObject(COUNT_USER_EMAIL_QUERY, Map.of("email", email), Integer.class);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = getUserByEmail(email);
        if (user == null) {
            log.error("User not found: {}", email);
            throw new UsernameNotFoundException("User not found: " + email);

        } else {
            log.info("User found by email: {}", email);
            return new UserPrincipal(user, roleRepository.getRoleByUserId(user.getId()).getPermission());
        }
    }

    public User getUserByEmail(String email) {
        try {
            User user = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
            return user;
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No user found with email: " + email);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred while creating user. Please try again later.");
        }
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        String expirationDate = DateFormatUtils.format(addDays(new Date(), 1), DATE_FORMAT);
        String verificationCode = randomAlphabetic(8).toUpperCase();
        try {
            jdbc.update(DELETE_TWO_FACTOR_VERIFICATION_CODE_BY_USER_ID_QUERY, Map.of("id", user.getId()));
            jdbc.update(INSERT_VERIFICATION_CODE_QUERY, Map.of("userId", user.getId(), "code", verificationCode, "expression_date", expirationDate));
            sendSms(user.getPhone(), "From: SecureCapita \nVerification code \n" + verificationCode);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred while creating user. Please try again later.");
        }
    }

    @Override
    public User verifyCode(String email, String code) {
        if (isVerificationCodeExpired(code)) {
            throw new ApiException("Verification code expired. Please login again.");
        }
        try {
            User userByCode = jdbc.queryForObject(SELECT_USER_BY_CODE_QUERY, Map.of("code", code), new UserRowMapper());
            User userByEmail = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
            if (userByCode.getEmail().equalsIgnoreCase(userByEmail.getEmail())) {
                jdbc.update(DELETE_CODE, Map.of("code", code));
                log.info("user code deleted.");
                return userByEmail;
            } else {
                throw new ApiException("Invalid verification code. Please try again later.");
            }
        } catch (EmptyResultDataAccessException e) {
            throw new ApiException("No user found with email: " + email);
        } catch (Exception e) {
            throw new ApiException("An error occurred. Please try again later.");
        }
    }

    private Boolean isVerificationCodeExpired(String code) {
        try {
            return jdbc.queryForObject(SELECT_CODE_EXPIRATION_DATE_QUERY, Map.of("code", code), Boolean.class);

        } catch (EmptyResultDataAccessException e) {
            throw new ApiException("This code is not valid. Please login again.");
        } catch (Exception e) {
            throw new ApiException("An error occurred. Please try again later.");
        }
    }
}
