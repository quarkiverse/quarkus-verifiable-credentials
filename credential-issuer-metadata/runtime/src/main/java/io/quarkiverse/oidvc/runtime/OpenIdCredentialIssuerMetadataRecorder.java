package io.quarkiverse.oidvc.runtime;

import java.util.Optional;
import java.util.function.Supplier;

import io.quarkiverse.oidvc.CredentialIssuerMetadata;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.common.runtime.OidcTlsSupport;
import io.quarkus.oidc.runtime.OidcConfig;
import io.quarkus.oidc.runtime.OidcTenantConfig;
import io.quarkus.proxy.ProxyConfigurationRegistry;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.ext.web.client.WebClient;

@Recorder
public class OpenIdCredentialIssuerMetadataRecorder {

    private static final String CREDENTIAL_ISSUER_METADATA_PATH = "/.well-known/openid-credential-issuer";

    private final RuntimeValue<OidcConfig> oidcConfig;
    private final RuntimeValue<OpenIdCredentialIssuerMetadataConfig> oidvcConfig;

    public OpenIdCredentialIssuerMetadataRecorder(final RuntimeValue<OidcConfig> oidcConfig,
            final RuntimeValue<OpenIdCredentialIssuerMetadataConfig> oidvcConfig) {
        this.oidcConfig = oidcConfig;
        this.oidvcConfig = oidvcConfig;
    }

    public Supplier<CredentialIssuerMetadata> setup(Supplier<Vertx> vertx, Supplier<TlsConfigurationRegistry> registry,
            Supplier<ProxyConfigurationRegistry> proxyConfigurationRegistrySupplier) {
        OidcTenantConfig oidcTenantConfig = oidcConfig.getValue().namedTenants().get(OidcConfig.DEFAULT_TENANT_KEY);
        String authServerUrl = OidcCommonUtils.getAuthServerUrl(oidcTenantConfig);

        WebClientOptions options = new WebClientOptions();

        OidcCommonUtils.setHttpClientOptions(oidcTenantConfig, options,
                OidcTlsSupport.of(registry.get()).forConfig(oidcTenantConfig.tls()),
                proxyConfigurationRegistrySupplier.get());

        WebClient webClient = WebClient.create(new io.vertx.mutiny.core.Vertx(vertx.get()), options);

        String baseCredentialIssuerUrl = oidvcConfig.getValue().credentialIssuerUrl().orElse(authServerUrl);

        String credentialIssuerMetadataUrl = OidcCommonUtils.getOidcEndpointUrl(baseCredentialIssuerUrl,
                Optional.of(CREDENTIAL_ISSUER_METADATA_PATH));

        CredentialIssuerMetadata metadata = webClient.getAbs(credentialIssuerMetadataUrl).send().onItem()
                .transform(r -> new CredentialIssuerMetadata(authServerUrl, r.bodyAsJsonObject()))
                .await().indefinitely();

        return new Supplier<CredentialIssuerMetadata>() {
            @Override
            public CredentialIssuerMetadata get() {
                return metadata;
            }
        };
    }
}
