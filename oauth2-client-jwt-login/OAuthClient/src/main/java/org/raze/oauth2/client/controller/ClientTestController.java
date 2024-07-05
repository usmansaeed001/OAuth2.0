package org.raze.oauth2.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Usman
 * @created 7/1/2024 - 3:19 AM
 * @project oauth2
 */

@RestController
public class ClientTestController {
    @Autowired
    private WebClient webClient;

    @GetMapping(value = "/client/test")
    public Map<String, Object> getArticles(@RegisteredOAuth2AuthorizedClient("oauth2client") OAuth2AuthorizedClient authorizedClient) {
        return this.webClient
                .get()
                .uri("http://127.0.0.1:8090/resource/test")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }

    @GetMapping(value = "/client/claim")
    public Map<String, Object> getClaims(@RegisteredOAuth2AuthorizedClient("oauth2client") OAuth2AuthorizedClient authorizedClient) {
        return this.webClient
                .get()
                .uri("http://127.0.0.1:8090/resource/claim")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }
}
