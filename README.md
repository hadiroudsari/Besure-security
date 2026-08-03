# Besure Security

A lightweight authorization framework inspired by Spring Security. It focuses on making JWT authentication and role-based authorization easy to understand, configure, and extend.
Not ready for production.

#### Running Keycloak with Docker

Start a local Keycloak instance for development:
```
docker run --name keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -p 8180:8180 \
  quay.io/keycloak/keycloak:26.7.0 \
  start-dev \
  --http-port=8180
```

Access Keycloak

Once the container is running, open:

http://localhost:8180

Login Credentials

Username: admin

Password: admin

Import the realm configuration(realm-import.json) file to create a new realm called quickstart

store access token:
```
export access_token=$(\
curl -X POST http://localhost:8180/realms/quickstart/protocol/openid-connect/token \
-H 'content-type: application/x-www-form-urlencoded' \
-d 'client_id=authz-servlet&client_secret=secret' \
-d 'username=jdoe&password=jdoe&grant_type=password' | jq --raw-output '.access_token' \
)
```

```
curl http://localhost:8080/hello \
-H "Authorization: Bearer "$access_token
```