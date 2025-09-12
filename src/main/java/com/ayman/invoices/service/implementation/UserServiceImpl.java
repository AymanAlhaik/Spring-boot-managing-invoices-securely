package com.ayman.invoices.service.implementation;

import com.ayman.invoices.domain.Role;
import com.ayman.invoices.domain.User;
import com.ayman.invoices.dto.UserDTO;
import com.ayman.invoices.dtomapper.UserDTOMapper;
import com.ayman.invoices.repository.RoleRepository;
import com.ayman.invoices.repository.UserRepository;
import com.ayman.invoices.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static com.ayman.invoices.dtomapper.UserDTOMapper.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final RoleRepository<Role> roleRepository;
    private final UserRepository<User> userRepository;

    @Override
    public UserDTO createUser(User user) {
        User createdUser = userRepository.create(user);
        return mapToUserDTO(createdUser);
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        User user = userRepository.getUserByEmail(email);
        return mapToUserDTO(user);
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        userRepository.sendVerificationCode(user);
    }

    @Override
    public UserDTO verifyCode(String email, String code) {
       return mapToUserDTO(userRepository.verifyCode(email, code));
    }
    private UserDTO mapToUserDTO(User user) {
        return fromUser(user, roleRepository.getRoleByUserId(user.getId()));
    }
}
