package io.quarkiverse.oidvp.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;

/**
 * Configuration for OpenId Verifiable Presentations.
 */
@ConfigMapping(prefix = "quarkus.oidvp")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface OpenIdVerifiablePresentationsConfig {

    /**
     * Absolute credential issuer url
     */
    Optional<String> credentialIssuerUrl();

}
