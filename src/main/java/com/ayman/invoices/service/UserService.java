package com.ayman.invoices.service;

import com.ayman.invoices.domain.User;
import com.ayman.invoices.dto.UserDTO;

public interface UserService {
    UserDTO createUser(User user);
    UserDTO getUserByEmail(String email);
}
/* youi aer */