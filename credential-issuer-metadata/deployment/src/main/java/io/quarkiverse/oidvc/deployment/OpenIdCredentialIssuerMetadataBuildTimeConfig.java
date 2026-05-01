package io.quarkiverse.oidvc.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Build time configuration for OpenID Credential Issuer Metadata.
 */
@ConfigMapping(prefix = "quarkus.oidvc")
@ConfigRoot
public interface OpenIdCredentialIssuerMetadataBuildTimeConfig {
    /**
     * If the OpenID Credential Issuer Metadata extension is enabled.
     */
    @WithDefault("true")
    boolean enabled();
}
