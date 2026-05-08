package io.quarkiverse.oidvp.runtime;

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

}
