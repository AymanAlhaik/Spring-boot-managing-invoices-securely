package com.ayman.invoices.repository.implementation;

import com.ayman.invoices.domain.User;
import com.ayman.invoices.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl implements UserRepository<User> {
    private final NamedParameterJdbcTemplate jdbc;
    @Override
    public User create(User data) {
        //check the email is unique
        //save new user
        //add role to the user
        //send verification url
        //save url in verification table
        //send email to user with verification url
        //return newly created user
        return null;
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
}
