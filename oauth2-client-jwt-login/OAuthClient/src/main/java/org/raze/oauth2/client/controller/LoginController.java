package org.raze.oauth2.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

/**
 * @author Usman
 * @created 7/1/2024 - 3:19 AM
 * @project oauth2
 */

@RestController
public class LoginController {
    @Autowired
    private WebClient webClient;

    record Data(OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken){}
    @GetMapping(value = "/login")
    public Map<String, Object> getArticles(@RegisteredOAuth2AuthorizedClient("oauth-client") OAuth2AuthorizedClient authorizedClient) {
        Data data = new Data(authorizedClient.getAccessToken(), authorizedClient.getRefreshToken());
        return Map.of("data", data);
    }
}
