package com.example.demo.controller;

import com.example.demo.dto.AuthResponse;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.Mensaje;
import com.example.demo.dto.NewUser;
import com.example.demo.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@CrossOrigin("http://localhost:4200/")
public class AuthController {

    private final AuthService authService;

    @PostMapping(value = "login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request)
    {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping(value = "add")
    public ResponseEntity<AuthResponse> add(@Valid @RequestBody NewUser request, BindingResult bindingResult){
        if(bindingResult.hasErrors())
            return new ResponseEntity(new Mensaje("Campos vacios o el email es invalido"), HttpStatus.BAD_REQUEST);
        if(authService.existsByEmail(request.getEmail()))
            return new ResponseEntity(new Mensaje("Este email ya se encuentra registrado"), HttpStatus.BAD_REQUEST);
        else{
            return ResponseEntity.ok(authService.addnewUser(request));
        }
    }
}
