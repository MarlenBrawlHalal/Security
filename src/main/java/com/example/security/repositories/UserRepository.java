package com.example.security.repositories;

import com.example.security.users.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

  Optional<UserEntity> findByEmail(String email);
}
