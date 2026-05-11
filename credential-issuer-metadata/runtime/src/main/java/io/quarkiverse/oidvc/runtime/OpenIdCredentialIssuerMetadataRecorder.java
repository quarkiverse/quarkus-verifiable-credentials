package io.quarkiverse.oidvc.runtime;

import java.util.Optional;
import java.util.function.Supplier;

import io.quarkiverse.oidvc.CredentialIssuerMetadata;
import io.quarkus.proxy.ProxyConfiguration;
import io.quarkus.proxy.ProxyConfigurationRegistry;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.quarkus.tls.runtime.config.TlsConfigUtils;
import io.vertx.core.Vertx;
import io.vertx.core.net.ProxyOptions;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.ext.web.client.WebClient;

@Recorder
public class OpenIdCredentialIssuerMetadataRecorder {

    private static final String CREDENTIAL_ISSUER_METADATA_PATH = "/.well-known/openid-credential-issuer";

    private final RuntimeValue<OpenIdCredentialIssuerMetadataConfig> config;

    public OpenIdCredentialIssuerMetadataRecorder(final RuntimeValue<OpenIdCredentialIssuerMetadataConfig> config) {
        this.config = config;
    }

    public Supplier<CredentialIssuerMetadata> setup(Supplier<Vertx> vertx,
            Supplier<TlsConfigurationRegistry> tlsRegistry,
            Supplier<ProxyConfigurationRegistry> proxyRegistry) {
        String credentialIssuerUrl = removeTrailingSlash(config.getValue().credentialIssuerUrl());
        String metadataUrl = credentialIssuerUrl + CREDENTIAL_ISSUER_METADATA_PATH;

        WebClientOptions options = new WebClientOptions();

        Optional<String> tlsConfigName = config.getValue().tlsConfigurationName();
        if (tlsConfigName.isPresent()) {
            Optional<TlsConfiguration> tlsConfig = tlsRegistry.get().get(tlsConfigName.get());
            if (tlsConfig.isPresent()) {
                TlsConfigUtils.configure(options, tlsConfig.get());
            }
        }

        Optional<ProxyConfiguration> proxyConfig = proxyRegistry.get()
                .get(config.getValue().proxyConfigurationName());
        if (proxyConfig.isPresent()) {
            ProxyConfiguration pc = proxyConfig.get();
            ProxyOptions proxyOptions = new ProxyOptions()
                    .setHost(pc.host())
                    .setPort(pc.port());
            pc.username().ifPresent(proxyOptions::setUsername);
            pc.password().ifPresent(proxyOptions::setPassword);
            options.setProxyOptions(proxyOptions);
        }

        WebClient webClient = WebClient.create(new io.vertx.mutiny.core.Vertx(vertx.get()), options);

        CredentialIssuerMetadata metadata = webClient.getAbs(metadataUrl).send().onItem()
                .transform(r -> new CredentialIssuerMetadata(credentialIssuerUrl, r.bodyAsJsonObject()))
                .await().indefinitely();

        return new Supplier<CredentialIssuerMetadata>() {
            @Override
            public CredentialIssuerMetadata get() {
                return metadata;
            }
        };
    }

    private static String removeTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
