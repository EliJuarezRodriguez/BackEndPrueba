package com.example.demo.service;

import com.example.demo.dto.AuthResponse;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.NewUser;
import com.example.demo.entity.PersonEntity;
import com.example.demo.entity.UserEntity;
import com.example.demo.enums.RolName;
import com.example.demo.jwt.TokenRepository;
import com.example.demo.jwt.TokenType;
import com.example.demo.jwt.token;
import com.example.demo.repository.PersonRepository;
import com.example.demo.repository.UserRepository;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private EntityManager entityManager;
    private final UserRepository userRepository;
    private final PersonRepository personRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    public Optional<UserEntity> getByEmail(String email){
        return userRepository.findByEmail(email);
    }

    public boolean existsByEmail(String email){
        return userRepository.existsByEmail(email);
    }

    public AuthResponse addnewUser(NewUser request){
        UserEntity user = UserEntity.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode( request.getPassword()))
                .phone(request.getPhone())
                .role(RolName.ROLE_USER_INTERMEDIO)
                .build();
        PersonEntity user1 = PersonEntity.builder()
                .username(request.getUsername())
                .apellidoPa(request.getApellidoPa())
                .apellidoMa(request.getApellidoMa())
                .fechaNacimiento(request.getFechaNacimiento())
                .build();
        user.setPersonEntity(user1);
        var saveUser = userRepository.save(user);
        personRepository.save(user1);
        var jwtToken = jwtService.generateToken(user);
        saveUserToken(saveUser, jwtToken);
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()));
        UserDetails user=userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens((UserEntity) user);
        saveUserToken((UserEntity) user,jwtToken);
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }


    private void saveUserToken(UserEntity userEntity, String jwtToken) {
        var Token = token.builder()
                .userEntity(userEntity)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(Token);
    }


    private void revokeAllUserTokens(UserEntity userEntity) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(userEntity.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
