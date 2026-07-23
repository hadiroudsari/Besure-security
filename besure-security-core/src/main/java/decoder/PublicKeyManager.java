package decoder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PublicKeyManager {

    private static final PublicKeyManager INSTANCE = new PublicKeyManager();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final String jwkSetUri =
            "http://localhost:8180/realms/quickstart/protocol/openid-connect/certs";

    private final Map<String, RSAPublicKey> cachedPublicKeys = new ConcurrentHashMap<>();

    private PublicKeyManager() {
        init();
    }

    public static PublicKeyManager getInstance() {
        return INSTANCE;
    }

    private void init() {
        try {

            String jwksJson = new String(
                    URI.create(jwkSetUri).toURL().openStream().readAllBytes(), // @todo change with httpclient and  timeout and set timeout.
                    StandardCharsets.UTF_8
            );
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            JsonNode keys = objectMapper.readTree(jwksJson).get("keys");

            for (JsonNode key : keys) {
                String kid = key.get("kid").asText();
                String n = key.get("n").asText();
                String e = key.get("e").asText();

                byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
                byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

                BigInteger modulus = new BigInteger(1, modulusBytes);
                BigInteger exponent = new BigInteger(1, exponentBytes);

                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);

                RSAPublicKey publicKey =
                        (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

                cachedPublicKeys.put(kid, publicKey);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load public keys from Keycloak", ex);
        }
    }

    public RSAPublicKey getPublicKey(String kid) {

        RSAPublicKey publicKey = cachedPublicKeys.get(kid);

        if (publicKey != null) {
            return publicKey;
        }

        refreshKeys();
        publicKey = cachedPublicKeys.get(kid);

        if (publicKey != null) {
            return publicKey;
        }

        throw new IllegalArgumentException(
                "No public key found for kid: " + kid);
    }

    private void refreshKeys() {
        cachedPublicKeys.clear(); // @todo check if cache get clear and init failed problem.
        init();
    }
}