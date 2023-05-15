package com.springboot.jwt.dto;

import lombok.Data;

@Data
public class LoginReqDto {

	private String username;
	private String password;
}