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
     * Absolute credential issuer URL
     */
    String credentialIssuerUrl();

    /**
     * Named TLS configuration to use for connecting to the credential issuer
     */
    Optional<String> tlsConfigurationName();

    /**
     * Named proxy configuration to use for connecting to the credential issuer
     */
    Optional<String> proxyConfigurationName();

}
