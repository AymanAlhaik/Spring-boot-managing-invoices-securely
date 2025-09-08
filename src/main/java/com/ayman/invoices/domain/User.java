package com.ayman.invoices.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
//exclude fields that have default values (null, false, 0, [], {}) from being returned as json
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class User {
    private Long id;
    @NotNull(message = "First name can't be empty")
    private String firstName;
    @NotNull(message = "Last name can't be empty")
    private String lastName;
    @NotNull(message = "Email can't be empty")
    @Email(message = "Invalid email. please enter a valid email address")
    private String email;
    @NotNull(message = "Password can't be empty")
    private String password;
    private String phone;
    private String address;
    private String title;
    private String bio;
    private String imageUrl;
    private boolean enabled;
    private boolean isNotLocked;
    private boolean isUsingMfa;
    private LocalDateTime createdAt;
}
