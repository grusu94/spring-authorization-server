package com.github.grusu94.spring.authorization.server.oauth2.authentication.jwt;

import com.github.grusu94.spring.authorization.server.oauth2.config.OAuth2ClientsProperties;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.io.File;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtConfig {

    private static final String JKS = "JKS";

    private final OAuth2ClientsProperties clientsProperties;

    public JwtConfig(OAuth2ClientsProperties clientsProperties) {
        this.clientsProperties = clientsProperties;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(JKS);
        keyStore.load(getFileOrClasspath(clientsProperties.getJwtKeystorePath()).getInputStream(),
                clientsProperties.getJwtKeystorePassword().toCharArray());

        final RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(clientsProperties.getJwtKeyPair(), clientsProperties.getJwtKeystorePassword().toCharArray());
        final RSAPublicKey publicKey = (RSAPublicKey) keyStore.getCertificate(clientsProperties.getJwtKeyPair()).getPublicKey();

        final RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(clientsProperties.getJwtKeyPair())
                .build();

        final JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder) {
        return new DelegatingOAuth2TokenGenerator(
                new JwtGenerator(jwtEncoder),
                new OAuth2RefreshTokenGenerator()
        );
    }

    private static Resource getFileOrClasspath(final String uri) {
        final File file = new File(uri);
        if (file.exists()) {
            return new FileSystemResource(file);
        } else {
            return new ClassPathResource(uri);
        }
    }
}
