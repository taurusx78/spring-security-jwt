package com.springboot.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springboot.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {

	// findBy 규칙
	// SELECT * FROM user WHERE username = ?
	User findByUsername(String username);
}
