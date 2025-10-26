package com.github.grusu94.spring.authorization.server.oauth2.config;

import com.github.grusu94.spring.authorization.server.oauth2.authentication.granttype.OAuth2UsernamePasswordAuthenticationConverter;
import com.github.grusu94.spring.authorization.server.oauth2.authentication.granttype.OAuth2UsernamePasswordAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.List;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    private final OAuth2ClientsProperties clientsProperties;

    public AuthorizationServerConfig(OAuth2ClientsProperties clientsProperties) {
        this.clientsProperties = clientsProperties;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      OAuth2AuthorizationService authorizationService,
                                                                      OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                                                      UserDetailsService userDetailsService,
                                                                      PasswordEncoder passwordEncoder) throws Exception {

        final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        authorizationServerConfigurer
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage(null))
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .authenticationProviders(providers ->
                                providers.add(new OAuth2UsernamePasswordAuthenticationProvider(
                                        authorizationService,
                                        tokenGenerator,
                                        userDetailsService,
                                        passwordEncoder
                                )))
                        .accessTokenRequestConverter(getOAuth2AuthenticationConverter())
                );

        http.apply(authorizationServerConfigurer);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/oauth2/token").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        final List<RegisteredClient> registeredClients = clientsProperties.getRegisteredClients().values().stream().toList();
        return new InMemoryRegisteredClientRepository(registeredClients);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    private AuthenticationConverter getOAuth2AuthenticationConverter() {

        List<AuthenticationConverter> delegates = List.of(
                new OAuth2RefreshTokenAuthenticationConverter(),
                new OAuth2UsernamePasswordAuthenticationConverter(),
                new OAuth2ClientCredentialsAuthenticationConverter(),
                new OAuth2AuthorizationCodeAuthenticationConverter()
        );

        return new DelegatingAuthenticationConverter(delegates);
    }

}
