# Application Requirements (Authentication & Authorization)

## 🧩 General System Requirements

- Support multi-user architecture with unique identification
- Secure authentication with password and multi-factor authentication (MFA)
- Role-based access control for permission management
- Audit logging of user actions and system events
- Account lifecycle management (verification, password reset, MFA)
- Scalable and maintainable schema design
- Data integrity via constraints and foreign keys
- Localization support (UTF8MB4 encoding, timezone setting)

---

##  Users Table Requirements

- Store user profile information: first name, last name, email, phone, address, title, bio
- Ensure unique email addresses for login and communication
- Support account status flags:
   - `enabled`: account activation
   - `non_locked`: account lock status
   - `using_mfa`: MFA usage flag
- Track account creation time (`created_at`)
- Provide default profile image URL
- Secure password storage (with potential for hashing)
- Enforce data validation (length limits, required fields)

---

##  Roles & Permissions Requirements

- Define distinct roles (e.g., Admin, User, Customer)
- Associate permissions with each role (e.g., `user:read`, `customer:delete`)
- Ensure role names are unique
- Prevent deletion of roles that are actively assigned

---

##  UserRoles Table Requirements

- Enable one-to-one mapping between users and roles
- Maintain referential integrity between users and roles
- Cascade updates to maintain consistency
- Restrict deletion of roles that are in use
- Enforce uniqueness of role assignment per user

---

##  Events & UserEvents Requirements

- Track user activity and system events (e.g., login attempts, profile updates)
- Define controlled list of event types using `CHECK` constraints
- Store event descriptions for audit purposes
- Link events to users with device and IP metadata
- Timestamp each event (`created_at`)
- Prevent deletion of event types that are referenced

---

##  AccountVerifications Requirements

- Support email verification via unique URLs
- Ensure one verification record per user
- Maintain referential integrity with Users table

---

##  ResetPasswordVerifications Requirements

- Enable secure password reset via unique URLs
- Include expiration timestamps for reset links
- Ensure one active reset record per user

---

##  TwoFactorVerifications Requirements

- Support MFA via verification codes
- Include expiration timestamps for codes
- Ensure one active MFA record per user
- Enforce code uniqueness to prevent reuse

---

##  Design Considerations

- Normalize data to avoid duplication and improve maintainability
- Use constraints and defaults to enforce security and data integrity
- Modular schema allows easy extension (e.g., new event types, roles)
- Full traceability of user actions for audit and compliance