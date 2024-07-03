package com.raze.config;

import com.raze.repository.JdbcClientRegistrationRepository;
import com.raze.repository.OAuth2ClientRoleRepository;
import com.raze.service.AuthorityMappingOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Default Spring Web Security Configuration
 *
 * @author: Raze
 */
@Configuration(proxyBeanMethods = false)
public class Oauth2ClientConfig {
	/**
	 * Extended OAuth2 login mapping permission information.
	 *
	 * @param oAuth2ClientRoleRepository
	 * @return
	 */
	@Bean
	OAuth2UserService<OAuth2UserRequest, OAuth2User> auth2UserService(OAuth2ClientRoleRepository oAuth2ClientRoleRepository) {
		return new AuthorityMappingOAuth2UserService(oAuth2ClientRoleRepository);
	}

	/**
	 * Persistent GitHub Client.
	 * The registrationId is specified in the {@link ClientRegistration#withRegistrationId(String registrationId) ClientRegistration.builder.registrationId
	 * ("github")}. This ID is used to identify this particular client registration.The {baseUrl} placeholder usually represents the base URL of your
	 * application. This is derived from the current request context. When a request is made to your application, Spring Security uses the request's URL to
	 * determine the base URL. The {action} placeholder typically refers to the action being performed, such as login or authorize. This is determined by the
	 * endpoint handling the OAuth2 flow. placeholder will be populated by
	 * {@link org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
	 * OAuth2AuthorizationRequestResolver}
	 *
	 * @param jdbcTemplate
	 * @return
	 */
	@Bean
	ClientRegistrationRepository clientRegistrationRepository(JdbcTemplate jdbcTemplate) {
		JdbcClientRegistrationRepository jdbcClientRegistrationRepository = new JdbcClientRegistrationRepository(jdbcTemplate);
		//Please apply for the correct clientId and clientSecret on github
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("github")
			.clientId("123456")
			.clientSecret("123456")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
			.scope("read:user")
			.authorizationUri("https://github.com/login/oauth/authorize")
			.tokenUri("https://github.com/login/oauth/access_token")
			.userInfoUri("https://api.github.com/user")
			.userNameAttributeName("login")
			.clientName("GitHub")
			.build();
		jdbcClientRegistrationRepository.save(clientRegistration);
		return jdbcClientRegistrationRepository;
	}

	/**
	 * Responsible for OAuth2AuthorizedClient persistence between web requests.
	 *
	 * @param jdbcTemplate
	 * @param clientRegistrationRepository
	 * @return
	 */
	@Bean
	OAuth2AuthorizedClientService authorizedClientService(JdbcTemplate jdbcTemplate, ClientRegistrationRepository clientRegistrationRepository) {
		return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
	}

	/**
	 * Used to save and persist authorized clients between requests.
	 *
	 * @param authorizedClientService
	 * @return
	 */
	@Bean
	OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
	}
}
