package com.github.grusu94.spring.authorization.server.oauth2.authentication.granttype;

import com.github.grusu94.spring.authorization.server.oauth2.authentication.util.OAuth2EndpointUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

public class OAuth2UsernamePasswordAuthenticationConverter implements AuthenticationConverter {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    @Override
    public Authentication convert(HttpServletRequest request) {

        final MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
        final String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);

        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        } else {
            final Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
            if (clientPrincipal == null) {
                OAuth2EndpointUtils.throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ErrorCodes.INVALID_CLIENT,
                        OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
            }

            final String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);

            if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
                OAuth2EndpointUtils.throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ParameterNames.SCOPE,
                        ERROR_URI
                );
            }

            Set<String> requestedScopes = null;
            if (StringUtils.hasText(scope)) {
                requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
            }

            final Map<String, Object> additionalParameters = new HashMap<>();
            parameters.forEach((key, value) -> {
                if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.SCOPE)) {
                    additionalParameters.put(key, value.size() == 1 ? value.get(0) : value.toArray(new String[0]));
                }
            });

            return new OAuth2UsernamePasswordAuthenticationToken(AuthorizationGrantType.PASSWORD, clientPrincipal, requestedScopes, additionalParameters);
        }
    }
}
