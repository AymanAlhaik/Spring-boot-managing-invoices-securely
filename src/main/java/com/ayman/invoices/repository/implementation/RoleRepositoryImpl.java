package com.ayman.invoices.repository.implementation;

import com.ayman.invoices.domain.Role;
import com.ayman.invoices.domain.User;
import com.ayman.invoices.domain.UserPrincipal;
import com.ayman.invoices.exception.ApiException;
import com.ayman.invoices.repository.RoleRepository;
import com.ayman.invoices.rowmapper.RoleRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.*;

import static com.ayman.invoices.enumeration.RoleType.ROLE_USER;
import static com.ayman.invoices.query.RoleQuery.*;

@Repository
@RequiredArgsConstructor
@Slf4j
public class RoleRepositoryImpl implements RoleRepository<Role> {
    private final NamedParameterJdbcTemplate jdbc;

    @Override
    public Role create(Role role) {
        return null;
    }

    @Override
    public Collection<Role> list(int page, int pageSize) {
        return List.of();
    }

    @Override
    public Role get(Long id) {
        return null;
    }

    @Override
    public Role update(Role data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
    }

    @Override
    public void addRoleToUser(Long userId, String roleName) {
        log.info("adding role: {} to user id: {}", roleName, userId);
        try {
            Role role = jdbc.queryForObject(SELECT_ROLE_BY_NAME_QUERY, Map.of("roleName", roleName),
                    new RoleRowMapper());
            jdbc.update(INSERT_ROLE_TO_USER_QUERY, Map.of("userId", userId, "roleId",
                    Objects.requireNonNull(role).getId()));
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No role found by name: " + ROLE_USER.name());
        } catch (Exception exception) {
            log.error(exception.getMessage(), exception);
            throw new ApiException("An error occurred while creating user. Please try again later.");
        }
    }

    @Override
    public Role getRoleByUserId(Long userId) {
        log.info("Getting role to user id: {}", userId);
        try {
            Role role = jdbc.queryForObject(SELECT_ROLE_BY_ID_QUERY, Map.of("id", userId),
                    new RoleRowMapper());
            log.error("===========the role is: {}", role.getPermission());
            return role;
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No role found by name: " + ROLE_USER.name());
        } catch (Exception exception) {
            log.error(exception.getMessage(), exception);
            throw new ApiException("An error occurred while creating user. Please try again later.");
        }
    }

    @Override
    public Role getRoleByUserEmail(String email) {
        return null;
    }

    @Override
    public void updateUserRole(Long userId, String roleName) {

    }

}
