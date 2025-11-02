package com.github.grusu94.spring.authorization.server.api;

import com.github.grusu94.spring.authorization.server.oauth2.authentication.granttype.OAuth2UsernamePasswordAuthenticationProvider;
import com.github.grusu94.spring.authorization.server.oauth2.authentication.granttype.OAuth2UsernamePasswordAuthenticationToken;
import com.github.grusu94.spring.authorization.server.oauth2.config.OAuth2ClientsProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final OAuth2ClientsProperties oAuth2ClientsProperties;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public UserController(OAuth2ClientsProperties oAuth2ClientsProperties, OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.oAuth2ClientsProperties = oAuth2ClientsProperties;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/oauth/token")
    public ResponseEntity<?> issueToken(@RequestParam String clientId, @RequestParam String clientSecret, @RequestParam String username, @RequestParam String password) {

        RegisteredClient registeredClient = oAuth2ClientsProperties.getRegisteredClient(clientId);
        Authentication auth = new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientSecret);

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("username", username);
        additionalParameters.put("password", password);

        OAuth2UsernamePasswordAuthenticationToken authentication =
                new OAuth2UsernamePasswordAuthenticationToken(AuthorizationGrantType.PASSWORD, auth, Collections.emptySet(), additionalParameters);

        OAuth2UsernamePasswordAuthenticationProvider usernamePasswordAuthProvider = new OAuth2UsernamePasswordAuthenticationProvider(
                authorizationService,
                tokenGenerator,
                userDetailsService,
                passwordEncoder
        );
        Authentication result = usernamePasswordAuthProvider.authenticate(authentication);

        if (result instanceof OAuth2AccessTokenAuthenticationToken tokenAuth) {
            return ResponseEntity.ok(tokenAuth.getAccessToken());
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

}
