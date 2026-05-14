package io.quarkiverse.oidvp.runtime;

import java.time.Duration;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;

/**
 * Configuration for OpenID Verifiable Presentations.
 */
@ConfigMapping(prefix = "quarkus.oidvp")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface VerifiablePresentationsConfig {

    /**
     * The verifier's public URL
     */
    String verifierHost();

    /**
     * Path for requesting a credential presentation
     */
    String requestCredentialPath();

    /**
     * Path for the presentation endpoint
     */
    String presentationPath();

    /**
     * Home path for the verifier application
     */
    String homePath();

    /**
     * Token verification configuration
     */
    Token token();

    @ConfigGroup
    interface Token {
        /**
         * Maximum age of the credential token since it was issued.
         * If set, the expiration time claim is not required.
         */
        Optional<Duration> age();
    }

}
