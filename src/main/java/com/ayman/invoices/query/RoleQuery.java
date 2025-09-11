package com.ayman.invoices.query;

public class RoleQuery {
    public static final String INSERT_ROLE_TO_USER_QUERY = "INSERT INTO UserRoles (user_id, role_id) VALUES (:userId, :roleId)";
    public static final String SELECT_ROLE_BY_NAME_QUERY = "SELECT * FROM Roles WHERE name = :roleName";
    public static final String SELECT_ROLE_BY_ID_QUERY =
            "SELECT r.id, r.name, r.permission FROM Roles r JOIN UserRoles ur ON r.id = ur.role_id JOIN Users u ON ur.user_id = u.id WHERE u.id = :id";
}
