package org.raze.oauth2.client.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/**
 * @author Usman
 * @created 7/1/2024 - 3:34 AM
 * @project oauth2
 */
@RestController
public class ResourceServerTestController {
	@GetMapping("/resource/claim")
	public Map<String, Object> getArticles(@AuthenticationPrincipal Jwt jwt) {
		System.out.println(jwt);
		return Collections.singletonMap("Resource Server", jwt.getClaims());
	}

	@GetMapping("/resource/test")
	public Map<String, Object> getArticles() {
		return Collections.singletonMap("Resource Server", "/resource/test");
	}
}
