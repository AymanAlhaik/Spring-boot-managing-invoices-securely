package com.ayman.invoices.service;

import com.ayman.invoices.domain.User;
import com.ayman.invoices.dto.UserDTO;

public interface UserService {
    UserDTO createUser(User user);
    UserDTO getUserByEmail(String email);

    void sendVerificationCode(UserDTO user);

    User getUser(String email);

    UserDTO verifyCode(String email, String code);
}
/* youi aer */