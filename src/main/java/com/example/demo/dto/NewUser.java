package com.example.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class NewUser {
    private String email;
    private String password;
    private int phone;
    private String username;
    private String apellidoPa;
    private String apellidoMa;
    private Date fechaNacimiento;
}