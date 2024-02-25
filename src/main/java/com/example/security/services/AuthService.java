package com.example.security.services;

import com.example.security.dto.AuthRequest;
import com.example.security.dto.AuthResponse;
import com.example.security.dto.RegisterRequest;
import com.example.security.repositories.UserRepository;
import com.example.security.users.Role;
import com.example.security.users.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserRepository userRepository;

  private final PasswordEncoder passwordEncoder;

  private final JwtService jwtService;

  private final AuthenticationManager authenticationManager;

  public AuthResponse register(RegisterRequest request) {

    //TODO: check if a user with request's email already exists in DB

    UserEntity user  = UserEntity.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(Role.USER)
        .build();

    userRepository.save(user);

    String jwt = jwtService.generateJwt(user);

    return AuthResponse.builder()
        .token(jwt)
        .build();
  }

  public AuthResponse authenticate(AuthRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );

    UserEntity user = userRepository.findByEmail(request.getEmail())
        .orElseThrow(() ->
            new UsernameNotFoundException("Email doesn't exist")
        );

    String jwt = jwtService.generateJwt(user);

    return AuthResponse.builder()
        .token(jwt)
        .build();
  }
}
