package decoder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class JWTTokenDecoder {

    PublicKeyManager publicKeyManager= PublicKeyManager.getInstance();

    private static final JWTTokenDecoder instance = new JWTTokenDecoder();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public static JWTTokenDecoder oneInstance() {
        return instance;
    }

    private JWTTokenDecoder() {
    }

    public DecodedToken decode(String token) throws JsonProcessingException {

        String[] parts = token.split("\\.");

        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token");
        }
        //decode part[0]
        Decoder decoder = Base64.getUrlDecoder();
        String headerJSON = new String(decoder.decode(parts[0]));
        String payloadJSON = new String(decoder.decode(parts[1]));
        Map<String, Object> payload =
                objectMapper.readValue(
                        payloadJSON,
                        new TypeReference<>() {
                        }
                );
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
        String signingInput = parts[0] + "." + parts[1];

        var decodedToken = new DecodedToken(
                Map.of("header", headerJSON),
                payload,
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

    private void validateToken(DecodedToken decodedToken) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String headerJson = decodedToken.header().get("header");
        JsonNode headerNode = objectMapper.readTree(headerJson);
        var kid = headerNode.get("kid").asText();

        RSAPublicKey publicKey = publicKeyManager.getPublicKey(kid);


        Signature verifier = Signature.getInstance("SHA256withRSA");

        verifier.initVerify(publicKey);

        verifier.update(decodedToken.signingInput().getBytes(StandardCharsets.UTF_8));

        if (!verifier.verify(decodedToken.signature())) {
            throw new IllegalArgumentException("Invalid JWT signature");
        }

    }

   public record DecodedToken(
            Map<String, String> header,
            Map<String, Object> payload,
            byte[] signature,
            String signingInput
    ) {
       @SuppressWarnings("unchecked")
       public Set<String> roles() {

           Map<String, Object> realmAccess = (Map<String, Object>) payload.get("realm_access");

           if (realmAccess == null) {
               return Set.of();
           }

           List<String> roles = (List<String>) realmAccess.get("roles");

           return roles == null ? Set.of() : Set.copyOf(roles);

       }

   }
}
