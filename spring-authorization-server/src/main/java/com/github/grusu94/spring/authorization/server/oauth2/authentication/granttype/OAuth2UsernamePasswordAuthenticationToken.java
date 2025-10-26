package com.github.grusu94.spring.authorization.server.oauth2.authentication.granttype;

import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.io.Serial;
import java.util.*;

@Getter
public class OAuth2UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 8641667982807174195L;
    private final AuthorizationGrantType authorizationGrantType;
    private final Authentication clientPrincipal;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;

    public OAuth2UsernamePasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType, Authentication clientPrincipal,
                                                     @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.authorizationGrantType = authorizationGrantType;
        this.clientPrincipal = clientPrincipal;
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
        this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }
}
