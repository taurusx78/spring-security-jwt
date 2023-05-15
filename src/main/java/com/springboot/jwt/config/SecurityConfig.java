package com.springboot.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

import com.springboot.jwt.config.jwt.JwtAuthenticationFilter;
import com.springboot.jwt.config.jwt.JwtAuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private AuthenticationConfiguration authenticationConfiguration;

	@Autowired
	private CorsFilter corsFilter;

	// @Configuration 클래스 내에 선언된 @Bean 메소드는 여러 번 호출돼도 싱글톤으로 관리되는 것을 보장함
	// 비밀번호를 암호화하는 BCryptPasswordEncoder 빈 생성
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// JwtAuthenticationFilter, JwtAuthorizationFilter 필터에서 사용할
	// AuthenticationManager를 빈으로 등록
	@Bean
	AuthenticationManager authenticationManager() throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용하지 안함 (JWT 기본 설정)
				.and()
				.formLogin().disable() // Form 로그인 인증 방식 사용 안함 (JWT 기본 설정)
				.httpBasic().disable() // Bearer 인증 방식 사용 (토큰 인증, JWT 기본 설정)
				// .addFilter(corsFilter) // CORS 필터 등록
				.addFilter(jwtAuthenticationFilter())
				.addFilter(jwtAuthorizationFilter())
				.authorizeRequests()
				.antMatchers("/api/v1/user/**")
				.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/manager/**")
				.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/admin/**")
				.access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll();

		return http.build();
	}

	// 아래 요청에 대해선 시큐리티 보안이 적용되지 않도록 설정 (WebIgnore 설정)
	@Bean
	WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().antMatchers("/images/**", "/js/**", "/css/**");
	}

	@Bean
	JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
		JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
		filter.setAuthenticationManager(authenticationManager());
		return filter;

	}

	@Bean
	JwtAuthorizationFilter jwtAuthorizationFilter() throws Exception {
		return new JwtAuthorizationFilter(authenticationManager());
	}
}