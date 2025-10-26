## Authorization server

### 1. Generate keystore.jks
   keytool -genkeypair \
   -alias mykey \
   -keyalg RSA \
   -keysize 2048 \
   -storetype JKS \
   -keystore keystore.jks \
   -validity 3650 \
   -storepass changeit \
   -keypass changeit \
   -dname "CN=AuthServer, OU=Dev, O=MyCompany, L=City, ST=State, C=US"

curl -X POST "http://localhost:9090/oauth2/token" \
-u "my-client:secret" \
-d "grant_type=password" \
-d "username=user" \
-d "password=pass" \
-d "scope=openid profile"