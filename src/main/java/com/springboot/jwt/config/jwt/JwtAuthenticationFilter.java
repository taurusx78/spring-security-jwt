package com.springboot.jwt.config.jwt;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.springboot.jwt.config.auth.PrincipalDetails;
import com.springboot.jwt.dto.LoginReqDto;

// username, password 입력 후 post 방식으로 /login 요청하면 UsernamePasswordAuthenticationFilter 필터가 동작함
// 이때 formLogin().disable()로 설정했기 때문에 따로 필터를 등록해야 함!

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter 인증 필터 실행");

		try {
			// 1. 요청 시 전송받은 JSON 데이터를 LoginReqDto 객체로 변환
			ObjectMapper om = new ObjectMapper();
			LoginReqDto loginReqDto = null;
			loginReqDto = om.readValue(request.getInputStream(), LoginReqDto.class);

			// 2. UsernamePasswordAuthenticationToken 객체 생성
			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
					loginReqDto.getUsername(), loginReqDto.getPassword());

			// 3. 해당 객체로 AuthenticationManager에게 전달해 인증 진행함
			// 이때 UserDetailsService의 loadUserByUsername() 실행됨
			// 로그인 성공 시 사용자 정보를 담은 authentication 객체 리턴받음
			return getAuthenticationManager().authenticate(authentication);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null; // 인증 실패
	}

	// attemptAuthentication() 실행 후 인증 성공 시 successfulAuthentication() 실행됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		PrincipalDetails principal = (PrincipalDetails) authResult.getPrincipal();

		// 4. JWT 토큰 생성
		String jwtToken = JWT.create()
				.withSubject(principal.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principal.getUser().getId())
				.withClaim("username", principal.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));

		// 5. HTTP 응답 메세지의 헤더와 바디에 데이터를 담아 클라이언트에게 전송
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
		response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json; charset=utf-8");
		PrintWriter out = response.getWriter();
        out.print("로그인 성공");
	}
}
