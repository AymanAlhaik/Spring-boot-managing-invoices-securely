package com.ayman.invoices.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
//exclude fields that have default values (null, false, 0, [], {}) from being returned as json
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class Role {
    private Long id;
    private String name;
    private String permission;
}
