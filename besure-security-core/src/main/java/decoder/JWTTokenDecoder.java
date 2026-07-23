package decoder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Map;

public class JWTTokenDecoder {


    private final String jwkSetUri = "http://localhost:8180/realms/quickstart/protocol/openid-connect/certs";

    PublicKeyManager cashedPublickey= PublicKeyManager.getInstance();

    private static final JWTTokenDecoder instance = new JWTTokenDecoder();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public static JWTTokenDecoder oneInstance() {
        return instance;
    }

    private JWTTokenDecoder() {
    }

    public DecodedToken decode(String token) {

        String[] parts = token.split("\\.");

        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token");
        }
        //decode part[0]
        Decoder decoder = Base64.getUrlDecoder();
        String headerJSON = new String(decoder.decode(parts[0]));
        String payloadJSON = new String(decoder.decode(parts[1]));
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
        String signingInput = parts[0] + "." + parts[1];

        var decodedToken = new DecodedToken(
                Map.of("header", headerJSON),
                Map.of("payload", payloadJSON),
                signatureBytes,
                signingInput
        );


        try {
            validateToken(decodedToken);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return decodedToken;

    }

    private void validateToken(DecodedToken decodedToken) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        String headerJson = decodedToken.header().get("header");
        JsonNode headerNode = objectMapper.readTree(headerJson);
        var kid = headerNode.get("kid").asText();

        RSAPublicKey publicKey = getPublicKeyFromKeycloak(kid);

        Signature verifier = Signature.getInstance("SHA256withRSA");

        verifier.initVerify(publicKey);

        verifier.update(decodedToken.signingInput().getBytes(StandardCharsets.UTF_8));

        boolean valid = verifier.verify(decodedToken.signature());

        if (!valid) {
            throw new IllegalArgumentException("Invalid JWT signature");
        }

    }

    private RSAPublicKey getPublicKeyFromKeycloak(String kid) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        String jwksJson = new String(
                URI.create(jwkSetUri).toURL().openStream().readAllBytes(),
                StandardCharsets.UTF_8
        );

        var keys = objectMapper.readTree(jwksJson).get("keys");
        for (JsonNode key : keys) {

            String keyId = key.get("kid").asText();

            if (kid.equals(keyId)) {

                String n = key.get("n").asText();
                String e = key.get("e").asText();

                byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
                byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

                BigInteger modulus = new BigInteger(1, modulusBytes);
                BigInteger exponent = new BigInteger(1, exponentBytes);

                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            }
        }

        throw new IllegalArgumentException("No matching public key found for kid: " + kid);
    }


    record DecodedToken(
            Map<String, String> header,
            Map<String, String> payload,
            byte[] signature,
            String signingInput
    ) {
    }


}
