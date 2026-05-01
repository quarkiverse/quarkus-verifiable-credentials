package io.quarkiverse.oidvc.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;

/**
 * Configuration for OpenId Credential Issuer Metadata.
 */
@ConfigMapping(prefix = "quarkus.oidvc")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface OpenIdCredentialIssuerMetadataConfig {

    /**
     * Absolute credential issuer url
     */
    Optional<String> credentialIssuerUrl();

}
