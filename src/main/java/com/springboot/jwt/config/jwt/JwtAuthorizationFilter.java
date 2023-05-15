package com.springboot.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

// 인증된 사용자인지 확인하는 필터
// 모든 요청은 해당 필터를 거침

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("JwtAuthorizationFilter 인가 필터 실행");
		
		String header = request.getHeader(JwtProperties.HEADER_STRING);

		// 1. Authorization 헤더가 있는지 확인
		// *** 인증이 필요한 페이지인지 확인 필요!
		if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		// 2. 토큰 검증 (검증 실패 시 SignatureVerificationException 예외 발생)
		String token = header.replace(JwtProperties.TOKEN_PREFIX, "");
		JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token);

		chain.doFilter(request, response);
	}
}
