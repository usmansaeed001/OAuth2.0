package org.raze.oauth2.client.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Usman
 * @created 7/1/2024 - 3:30 AM
 * @project oauth2
 */
@EnableWebSecurity
public class ResourceServerConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(registry -> registry.requestMatchers("/resource/test/**")
				.hasAuthority("SCOPE_message.read")
				.anyRequest()
				.permitAll()
				.anyRequest()
				.authenticated())
			.oauth2ResourceServer(configurer -> configurer.jwt(Customizer.withDefaults()));
		return http.build();
	}

}