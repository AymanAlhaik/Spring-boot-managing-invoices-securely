package com.ayman.invoices.service.implementation;

import com.ayman.invoices.domain.User;
import com.ayman.invoices.dto.UserDTO;
import com.ayman.invoices.dtomapper.UserDTOMapper;
import com.ayman.invoices.repository.UserRepository;
import com.ayman.invoices.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository<User> userRepository;
    private final UserDTOMapper userDTOMapper;
    @Override
    public UserDTO createUser(User user) {
        User createdUser = userRepository.create(user);
        return UserDTOMapper.fromUser(user);
    }
}
