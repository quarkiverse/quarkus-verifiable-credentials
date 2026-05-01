package io.quarkiverse.oidvp.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Build time configuration for OpenID Verifiable Presentations.
 */
@ConfigMapping(prefix = "quarkus.oidvp")
@ConfigRoot
public interface OpenIdVerifiablePresentationsBuildTimeConfig {
    /**
     * If the OpenID Verifiable Presentations extension is enabled.
     */
    @WithDefault("true")
    boolean enabled();
}
