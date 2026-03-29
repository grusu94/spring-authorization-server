# Spring Authorization Server

A comprehensive Spring Authorization Server implementation built with Spring Boot 3.1.12 and Spring Security OAuth2 that supports multiple authentication flows and grant types.

## Overview

This project implements an OAuth2 Authorization Server with support for:
- **Password Grant** - Resource Owner Password Credentials Flow
- **Authorization Code Grant** - OAuth2 Authorization Code Flow
- **Refresh Token Grant** - Token refresh mechanism
- **Client Credentials Grant** - Service-to-service authentication
- **Custom Grant Types** - Extended functionality for trusted clients

## Features

- **JWT Token Support** - Secure token generation and validation with JKS keystore
- **Multiple Client Configurations** - Support for multiple OAuth2 clients with different grant types
- **Custom Authentication Converters** - Custom implementation for username/password authentication
- **Token Enhancement** - Legacy claims token enhancer for backward compatibility
- **Spring Cloud OpenFeign Integration** - Feign client support for inter-service communication
- **Health & Actuator Endpoints** - Full Spring Boot Actuator integration
- **SSL/TLS Support** - Built-in HTTPS support with custom keystore

## Technology Stack

- **Java 17**
- **Spring Boot 3.1.12**
- **Spring Security 6.x** (OAuth2 Authorization Server)
- **Spring Cloud 2022.0.5** (OpenFeign)
- **Maven 3.x**
- **JUnit 5** (Testing)

## Project Structure

```
spring-authorization-server/
├── src/main/
│   ├── java/com/github/grusu94/spring/authorization/server/
│   │   ├── OAuth2ServerApplication.java       # Main application entry point
│   │   ├── api/
│   │   │   └── UserController.java            # REST API endpoints
│   │   ├── config/
│   │   │   ├── AuthorizationServerConfig.java # OAuth2 server configuration
│   │   │   ├── MyUserDetailsService.java      # User authentication service
│   │   │   └── OAuth2ClientsProperties.java   # Client configuration properties
│   │   └── oauth2/
│   │       ├── authentication/
│   │       │   ├── enhancer/
│   │       │   │   └── LegacyClaimsTokenEnhancer.java
│   │       │   ├── granttype/
│   │       │   │   ├── OAuth2UsernamePasswordAuthenticationConverter.java
│   │       │   │   ├── OAuth2UsernamePasswordAuthenticationProvider.java
│   │       │   │   └── OAuth2UsernamePasswordAuthenticationToken.java
│   │       │   └── jwt/
│   │       │       ├── JwtConfig.java
│   │       │       └── OAuth2PrincipalAuthenticationConverter.java
│   │       └── config/
│   │           └── AuthorizationServerConfig.java
│   └── resources/
│       ├── application.yml                    # Application configuration
│       └── keystore.jks                       # SSL/TLS keystore
└── pom.xml                                    # Maven configuration
```

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3.6.0 or higher

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/grusu94/spring-authorization-server.git
   cd spring-authorization-server
   ```

2. **Build the project**
   ```bash
   mvn clean package
   ```

3. **Run the application**
   ```bash
   mvn spring-boot:run
   ```
   
   Or run the JAR directly:
   ```bash
   java -jar spring-authorization-server/target/spring-authorization-server-3.1.0.jar
   ```

### Configuration

The server runs on port **9090** with HTTPS enabled. Key configuration is in `application.yml`:

- **Server Port:** 9090 (HTTPS)
- **Keystore:** `classpath:keystore.jks`
- **Keystore Password:** changeit
- **Key Password:** changeit

### Pre-configured OAuth2 Clients

The application comes with three pre-configured OAuth2 clients:

#### Client 1
- **Client ID:** client1
- **Client Secret:** abcdefgh1234
- **Grant Types:** refresh_token, password, custom_trusted
- **Scope:** client1, role.create
- **Token Validity:** 24 hours (access), 30 days (refresh)

#### Client 2
- **Client ID:** client2
- **Client Secret:** abcdefgh1235
- **Grant Types:** authorization_code, refresh_token, password, custom_trusted
- **Scope:** role.create
- **Token Validity:** 24 hours (access), 30 days (refresh)

#### Client 3
- **Client ID:** client3
- **Client Secret:** abcdefgh1236
- **Grant Types:** authorization_code, refresh_token, password, client_credentials
- **Scope:** client3, role.create
- **Token Validity:** 24 hours (access), 30 days (refresh)

## API Endpoints

### Health & Actuator
- `GET https://localhost:9090/actuator/health` - Health check endpoint
- `GET https://localhost:9090/actuator` - Actuator endpoints

### OAuth2 Token Endpoints
- `POST /oauth2/token` - Request access token
- `GET /oauth2/authorize` - Authorization endpoint
- `POST /oauth2/revoke` - Revoke token
- `GET /oauth2/jwks` - JWKS (JSON Web Key Set) endpoint

### User Management
- `GET /user` - Get current user information
- `POST /user/register` - Register new user (if enabled)

## Usage Examples

### Password Grant Flow

```bash
curl -X POST "https://localhost:9090/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=client1" \
  -d "client_secret=abcdefgh1234" \
  -d "username=user" \
  -d "password=password" \
  -d "scope=client1" \
  -k
```

### Client Credentials Grant Flow

```bash
curl -X POST "https://localhost:9090/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=client3" \
  -d "client_secret=abcdefgh1236" \
  -d "scope=client3" \
  -k
```

### Refresh Token

```bash
curl -X POST "https://localhost:9090/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=client1" \
  -d "client_secret=abcdefgh1234" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -k
```

## Development

### Building from Source

```bash
mvn clean install
```

### Running Tests

```bash
mvn test
```

### Building Docker Image (Optional)

```bash
mvn spring-boot:build-image
```

## Custom Authentication Flows

This project includes support for custom authentication flows through:

- **OAuth2UsernamePasswordAuthenticationConverter** - Converts username/password credentials
- **OAuth2UsernamePasswordAuthenticationProvider** - Authenticates using custom credentials
- **OAuth2UsernamePasswordAuthenticationToken** - Holds authentication token details

## Token Enhancement

The `LegacyClaimsTokenEnhancer` provides backward compatibility by adding legacy claims to JWT tokens.

## Troubleshooting

### HTTPS Certificate Warning
The default keystore uses a self-signed certificate. To suppress SSL warnings in development:
- Use the `-k` flag with curl
- Configure your client to trust self-signed certificates

### Port Already in Use
If port 9090 is already in use, modify `application.yml`:
```yaml
server:
  port: <new-port>
```

### Token Validation Issues
Ensure:
- The keystore file is in the classpath
- Keystore and key passwords match the configuration
- JWT configuration is correct in `JwtConfig.java`

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created by [grusu94](https://github.com/grusu94)

## Additional Resources

- [Spring Authorization Server Documentation](https://spring.io/projects/spring-authorization-server)
- [Spring Security OAuth2 Documentation](https://spring.io/projects/spring-security)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [JWT (JSON Web Tokens) - RFC 7519](https://tools.ietf.org/html/rfc7519)
