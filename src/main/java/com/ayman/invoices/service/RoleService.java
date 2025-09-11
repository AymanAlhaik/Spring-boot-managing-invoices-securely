package com.ayman.invoices.service;

import com.ayman.invoices.domain.Role;

public interface RoleService {
    Role getRoleByUserId(Long id);
}
