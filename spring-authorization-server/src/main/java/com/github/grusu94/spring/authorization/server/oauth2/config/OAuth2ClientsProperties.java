package com.github.grusu94.spring.authorization.server.oauth2.config;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@ConfigurationProperties(prefix = "oauth2")
@Component
@Getter
@Setter
public class OAuth2ClientsProperties {

    @NotNull
    private Map<String, ClientDetailsDto> clients;

    @NotEmpty
    private String jwtKeystorePath;

    private String jwtKeyPair;

    private String jwtKeystorePassword;

    private Map<String, RegisteredClient> registeredClients;

    @PostConstruct
    public void init() {
        if (clients != null) {
            registeredClients = new HashMap<>();
            for (Map.Entry<String, ClientDetailsDto> entry : clients.entrySet()) {
                final String clientId = entry.getKey();
                final ClientDetailsDto clientDetails = entry.getValue();

                final RegisteredClient.Builder builder =
                        RegisteredClient.withId(String.valueOf(UUID.randomUUID()))
                                .clientId(clientId)
                                .clientSecret(clientDetails.getClientSecret());

                // Add authorization grant types
                final Set<String> grantTypes = clientDetails.getAuthorizedGrantTypesAsSet();
                for (String grantType : grantTypes) {
                    switch (grantType.trim().toLowerCase()) {
                        case "refresh_token":
                            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                            break;
                        case "password":
                            builder.authorizationGrantType(AuthorizationGrantType.PASSWORD);
                            break;
                        case "client_credentials":
                            builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                            break;
                        case "authorization_code":
                            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                            break;
                        case "custom_trusted":
                            // Custom grant type - register as a new AuthorizationGrantType
                            builder.authorizationGrantType(new AuthorizationGrantType("custom_trusted"));
                            break;
                        default:
                            // Any other custom grant types
                            builder.authorizationGrantType(new AuthorizationGrantType(grantType.trim()));
                    }
                }

                final Set<String> scopes = clientDetails.getScopeAsSet();
                for (String scope : scopes) {
                    builder.scope(scope.trim());
                }

                final TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();

                if (clientDetails.getAccessTokenValiditySeconds() != null) {
                    tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(clientDetails.getAccessTokenValiditySeconds()));
                }

                if (clientDetails.getRefreshTokenValiditySeconds() != null) {
                    tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(clientDetails.getRefreshTokenValiditySeconds()));
                }

                builder.tokenSettings(tokenSettingsBuilder.build());

                builder.redirectUri("/");

                registeredClients.put(clientId, builder.build());
            }
        }
    }

    public RegisteredClient getRegisteredClient(String clientId) {
        return registeredClients != null ? registeredClients.get(clientId) : null;
    }

    @Getter
    @Setter
    public static class ClientDetailsDto {

        private String clientSecret;
        private String authorizedGrantTypes;
        private String scope;
        private Integer accessTokenValiditySeconds;
        private Integer refreshTokenValiditySeconds;

        public Set<String> getAuthorizedGrantTypesAsSet() {
            if (authorizedGrantTypes == null || authorizedGrantTypes.trim().isEmpty()) {
                return Set.of();
            }
            return Set.of(authorizedGrantTypes.split(","));
        }

        public Set<String> getScopeAsSet() {
            if (scope == null || scope.trim().isEmpty()) {
                return Set.of();
            }
            return Set.of(scope.split(","));
        }


    }
}
