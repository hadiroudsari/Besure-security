Running Keycloak with Docker

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