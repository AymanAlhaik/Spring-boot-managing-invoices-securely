package com.ayman.invoices.service.implementation;

import com.ayman.invoices.domain.Role;
import com.ayman.invoices.repository.RoleRepository;
import com.ayman.invoices.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {
    private final RoleRepository<Role> roleRepository;
    @Override
    public Role getRoleByUserId(Long id) {
        return roleRepository.getRoleByUserId(id);
    }
}
