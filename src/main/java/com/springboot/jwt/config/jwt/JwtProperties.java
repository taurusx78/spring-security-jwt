package com.springboot.jwt.config.jwt;

public interface JwtProperties {
	String SECRET = "또치";  // 우리 서버만 알고 있는 비밀값
	int EXPIRATION_TIME = 864000000;  // 10일 (단위: 1/1000초)
	String HEADER_STRING = "Authorization";
	String TOKEN_PREFIX = "Bearer ";
}