package com.springboot.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

// 자바스크립트 CORS(Cross-Origin Resource Sharing) 필터 설정
// CORS: SOP를 우회하여 웹 브라우저에서 다른 도메인 간에 자원을 공유할 수 있도록 허용하는 웹 보안 기술

@Configuration
public class CorsConfig {

	@Bean
	CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true); // 요청에 포함된 쿠키 및 인증 정보를 내 서버에서 사용할 수 있도록 허용
		config.addAllowedOrigin("*"); // 내 서버로 요청을 보낼 수 있는 출처(Origin) 설정
		config.addAllowedHeader("*"); // 내 서버로 요청을 보낼 수 있는 HTTP 헤더 설정
		config.addAllowedMethod("*"); // 내 서버로 요청을 보낼 수 있는 HTTP 메서드 설정
		source.registerCorsConfiguration("/api/**", config); // 해당 URL 패턴에 CORS 설정 등록
		return new CorsFilter(source);
	}
}
