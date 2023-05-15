package com.springboot.jwt.controller;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.jwt.model.User;
import com.springboot.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class RestApiController {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder encoder;

	@GetMapping("/home")
	public String home() {
		return "<h3>home</h3>";
	}
	
	@PostMapping("/token")
	public String token() {
		return "<h3>token</h3>";
	}
	
	@PostMapping("/join")
	public String join(@RequestBody User user) {
		user.setPassword(encoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입 완료";
	}
}
