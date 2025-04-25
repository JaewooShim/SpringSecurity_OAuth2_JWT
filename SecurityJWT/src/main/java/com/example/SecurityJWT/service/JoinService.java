package com.example.SecurityJWT.service;

import com.example.SecurityJWT.Model.UserEntity;
import com.example.SecurityJWT.dto.JoinDTO;
import com.example.SecurityJWT.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public JoinService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {
        if (userRepository.existsByUsername(joinDTO.username())) {
            return;
        }
        UserEntity user = new UserEntity();
        user.setUsername(joinDTO.username());
        user.setPassword(passwordEncoder.encode(joinDTO.password()));
        user.setRole("ROLE_ADMIN");
        userRepository.save(user);
    }
}
