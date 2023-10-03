package com.example.demo.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "persona")
public class PersonEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idPersona")
    private int idPersona;
    @NotBlank
    @Size(max = 50)
    @Column(name = "nombre")
    private String username;
    @NotBlank
    @Size(max = 50)
    @Column(name = "apellidoPa")
    private String apellidoPa;
    @NotBlank
    @Size(max = 50)
    @Column(name = "apellidoMa")
    private String apellidoMa;
    @Column(name = "fechaNacimiento")
    private Date fechaNacimiento;

    @OneToOne(mappedBy = "personEntity")
    private UserEntity userEntity;
}
