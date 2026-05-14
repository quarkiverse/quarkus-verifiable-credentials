package io.quarkiverse.oidvp.runtime;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;

import io.vertx.core.json.JsonObject;

public class CredentialJwtVerifier {

    private static final Logger LOG = Logger.getLogger(CredentialJwtVerifier.class);

    private final JwtConsumer jwtConsumer;
    private final Optional<Duration> tokenAge;

    public CredentialJwtVerifier(JsonWebKeySet jwks, Optional<Duration> tokenAge) {
        this.tokenAge = tokenAge;

        JwksVerificationKeyResolver keyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setVerificationKeyResolver(keyResolver)
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT,
                        AlgorithmIdentifiers.RSA_USING_SHA256,
                        AlgorithmIdentifiers.RSA_USING_SHA384,
                        AlgorithmIdentifiers.RSA_USING_SHA512,
                        AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
                        AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384,
                        AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512,
                        AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
                        AlgorithmIdentifiers.RSA_PSS_USING_SHA384,
                        AlgorithmIdentifiers.RSA_PSS_USING_SHA512,
                        AlgorithmIdentifiers.EDDSA))
                .setRelaxVerificationKeyValidation()
                .setSkipDefaultAudienceValidation();

        if (tokenAge.isEmpty()) {
            builder.setRequireExpirationTime();
        } else {
            builder.setRequireIssuedAt();
        }

        this.jwtConsumer = builder.build();
    }

    public JsonObject verify(String credentialJwt) throws InvalidJwtException {
        LOG.debug("Verifying credential JWT signature and claims");
        try {
            jwtConsumer.processToClaims(credentialJwt);
        } catch (InvalidJwtException e) {
            LOG.debugf("Credential JWT verification failed: %s", e.getMessage());
            throw e;
        }
        LOG.debug("Credential JWT signature and claims verification passed");

        JsonObject claims = decodeJwtContent(credentialJwt);
        verifyTokenAge(claims.getLong("iat"));
        return claims;
    }

    private void verifyTokenAge(Long iat) throws InvalidJwtException {
        if (tokenAge.isPresent() && iat != null) {
            long now = System.currentTimeMillis() / 1000;
            long age = now - iat;
            long maxAge = tokenAge.get().toSeconds();
            LOG.debugf("Token age check: age=%ds, maxAge=%ds", age, maxAge);
            if (age > maxAge) {
                String errorMessage = "Token age exceeds the configured token age property";
                LOG.debug(errorMessage);
                throw new InvalidJwtException(errorMessage,
                        List.of(new ErrorCodeValidator.Error(ErrorCodes.ISSUED_AT_INVALID_PAST, errorMessage)), null);
            }
        }
    }

    private static JsonObject decodeJwtContent(String jwt) {
        String[] parts = jwt.split("\\.");
        String json = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        return new JsonObject(json);
    }
}
