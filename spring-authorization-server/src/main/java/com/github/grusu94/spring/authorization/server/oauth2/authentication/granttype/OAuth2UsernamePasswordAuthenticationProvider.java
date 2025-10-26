package com.github.grusu94.spring.authorization.server.oauth2.authentication.granttype;

import com.github.grusu94.spring.authorization.server.oauth2.authentication.util.OAuth2AuthenticationProviderUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;

@Slf4j
public class OAuth2UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public OAuth2UsernamePasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                                        UserDetailsService userDetailsService,
                                                        PasswordEncoder passwordEncoder) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final OAuth2UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = (OAuth2UsernamePasswordAuthenticationToken) authentication;
        final OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(usernamePasswordAuthenticationToken);
        final RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        log.trace("Registered client retrieved");

        boolean noPasswordGrantType = ofNullable(registeredClient)
                .map(RegisteredClient::getAuthorizationGrantTypes)
                .stream()
                .flatMap(Collection::stream)
                .noneMatch(AuthorizationGrantType.PASSWORD::equals);
        if (noPasswordGrantType) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                    "Client is not authorized for grant type: password",
                    ERROR_URI));
        }

        final Authentication usernamePasswordAuthentication = getUsernamePasswordAuthentication(usernamePasswordAuthenticationToken);
        Set<String> authorizedScopes = registeredClient.getScopes();

        final Set<String> requestedScopes = Optional
                .ofNullable(usernamePasswordAuthenticationToken.getScopes())
                .orElse(Collections.emptySet());

        if (!requestedScopes.isEmpty()) {
            final Set<String> unauthorizedScopes = requestedScopes.stream()
                    .filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
                    .collect(Collectors.toSet());
            if (!unauthorizedScopes.isEmpty()) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
                        "Invalid scopes: " + String.join(", ", unauthorizedScopes),
                        ERROR_URI));
            }
            authorizedScopes = new LinkedHashSet<>(requestedScopes);
        }
        log.trace("Scopes validated");

        final DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(usernamePasswordAuthenticationToken);

        // Access token
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        final OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token.", ERROR_URI));
        } else {
            log.trace("Generated access token");

            final OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                    .principalName(usernamePasswordAuthentication.getName())
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .authorizedScopes(authorizedScopes)
                    .attribute(Principal.class.getName(), usernamePasswordAuthentication);

            final OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                    generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());


            if (generatedAccessToken instanceof ClaimAccessor) {
                authorizationBuilder.token(accessToken, (metadata) -> {
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor)generatedAccessToken).getClaims());
                });
            } else {
                authorizationBuilder.accessToken(accessToken);
            }

            // Refresh token
            OAuth2RefreshToken refreshToken = null;
            if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                    !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
                tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
                OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the refresh token.", ERROR_URI));
                }

                refreshToken = (OAuth2RefreshToken)generatedRefreshToken;
                authorizationBuilder.refreshToken(refreshToken);

                log.trace("Generated refresh token");
            }

            OidcIdToken idToken;
            if (requestedScopes.contains(OidcScopes.OPENID)) {
                tokenContext = tokenContextBuilder
                        .tokenType(new OAuth2TokenType("id_token"))
                        .authorization(authorizationBuilder.build())
                        .build();
                final OAuth2Token generatedIdToken = this.tokenGenerator.generate(tokenContext);
                if (!(generatedIdToken instanceof Jwt)) {
                    throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "The token generator failed to generate the ID token.", ERROR_URI));
                }

                idToken = new OidcIdToken(generatedIdToken.getTokenValue(), generatedIdToken.getIssuedAt(),
                        generatedIdToken.getExpiresAt(), ((Jwt)generatedIdToken).getClaims());
                authorizationBuilder.token(idToken, (metadata) -> {
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims());
                });

                log.trace("Generated id token");
            } else {
                idToken = null;
            }

            OAuth2Authorization authorization = authorizationBuilder.build();
            this.authorizationService.save(authorization);

            log.trace("Saved authorization");

            Map<String, Object> additionalParameters = Collections.emptyMap();
            if (idToken != null) {
                additionalParameters = Map.of(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
            }

            log.trace("Authenticated token request");

            return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Authentication getUsernamePasswordAuthentication(OAuth2UsernamePasswordAuthenticationToken oAuth2UsernamePasswordAuthenticationToken) {

        final Map<String, Object> additionalParameters = oAuth2UsernamePasswordAuthenticationToken.getAdditionalParameters();

        final String username = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
        final String password = (String) additionalParameters.get(OAuth2ParameterNames.PASSWORD);

        final UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,
                    "Invalid credentials", ERROR_URI));
        }

        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }
}
