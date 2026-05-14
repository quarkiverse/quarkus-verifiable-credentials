package io.quarkiverse.oidvp.runtime;

import java.util.Optional;
import java.util.function.Supplier;

import org.jboss.logging.Logger;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.lang.JoseException;

import io.quarkiverse.oidvc.CredentialIssuerMetadata;
import io.quarkiverse.oidvc.runtime.OpenIdCredentialIssuerMetadataConfig;
import io.quarkus.proxy.ProxyConfiguration;
import io.quarkus.proxy.ProxyConfigurationRegistry;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.quarkus.tls.runtime.config.TlsConfigUtils;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.ProxyOptions;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.ext.web.client.WebClient;

@Recorder
public class CredentialJwtVerifierRecorder {

    private static final Logger LOG = Logger.getLogger(CredentialJwtVerifierRecorder.class);

    private static final String JWT_VC_ISSUER_PATH = "/.well-known/jwt-vc-issuer";

    private final RuntimeValue<OpenIdCredentialIssuerMetadataConfig> metadataConfig;
    private final RuntimeValue<VerifiablePresentationsConfig> vpConfig;

    public CredentialJwtVerifierRecorder(RuntimeValue<OpenIdCredentialIssuerMetadataConfig> metadataConfig,
            RuntimeValue<VerifiablePresentationsConfig> vpConfig) {
        this.metadataConfig = metadataConfig;
        this.vpConfig = vpConfig;
    }

    public Supplier<CredentialJwtVerifier> setup(Supplier<Vertx> vertx,
            Supplier<TlsConfigurationRegistry> tlsRegistry,
            Supplier<ProxyConfigurationRegistry> proxyRegistry,
            Supplier<CredentialIssuerMetadata> credentialIssuerMetadata) {
        String credentialIssuerUrl = removeTrailingSlash(credentialIssuerMetadata.get().getCredentialIssuer());
        String jwksUrl = credentialIssuerUrl + JWT_VC_ISSUER_PATH;
        LOG.debugf("Fetching JWT VC Issuer metadata from %s", jwksUrl);

        WebClientOptions options = new WebClientOptions();

        Optional<String> tlsConfigName = metadataConfig.getValue().tlsConfigurationName();
        if (tlsConfigName.isPresent()) {
            LOG.debugf("Using TLS configuration: %s", tlsConfigName.get());
            Optional<TlsConfiguration> tlsConfig = tlsRegistry.get().get(tlsConfigName.get());
            if (tlsConfig.isPresent()) {
                TlsConfigUtils.configure(options, tlsConfig.get());
            } else {
                LOG.warnf("TLS configuration '%s' not found", tlsConfigName.get());
            }
        }

        Optional<ProxyConfiguration> proxyConfig = proxyRegistry.get()
                .get(metadataConfig.getValue().proxyConfigurationName());
        if (proxyConfig.isPresent()) {
            ProxyConfiguration pc = proxyConfig.get();
            LOG.debugf("Using proxy: %s:%d", pc.host(), pc.port());
            ProxyOptions proxyOptions = new ProxyOptions()
                    .setHost(pc.host())
                    .setPort(pc.port());
            pc.username().ifPresent(proxyOptions::setUsername);
            pc.password().ifPresent(proxyOptions::setPassword);
            options.setProxyOptions(proxyOptions);
        }

        WebClient webClient = WebClient.create(new io.vertx.mutiny.core.Vertx(vertx.get()), options);

        JsonObject jwtVcIssuer = webClient.getAbs(jwksUrl).send().onItem()
                .transform(r -> r.bodyAsJsonObject())
                .await().indefinitely();

        LOG.debugf("JWT VC Issuer response: %s", jwtVcIssuer.encode());

        String issuer = jwtVcIssuer.getString("issuer");
        LOG.debugf("JWT VC Issuer issuer: %s, expected credential issuer: %s", issuer, credentialIssuerUrl);
        if (issuer == null || !credentialIssuerUrl.equals(removeTrailingSlash(issuer))) {
            throw new RuntimeException(
                    "jwt-vc-issuer issuer '" + issuer + "' does not match credential issuer '" + credentialIssuerUrl + "'");
        }

        JsonObject jwksObject = jwtVcIssuer.getJsonObject("jwks");
        if (jwksObject == null) {
            throw new RuntimeException("jwt-vc-issuer response does not contain a jwks property");
        }

        JsonWebKeySet jwks;
        try {
            jwks = new JsonWebKeySet(jwksObject.encode());
        } catch (JoseException e) {
            throw new RuntimeException("Failed to parse JWKS from " + jwksUrl, e);
        }

        LOG.debugf("Loaded %d verification key(s) from JWT VC Issuer", jwks.getJsonWebKeys().size());
        if (LOG.isTraceEnabled()) {
            for (var key : jwks.getJsonWebKeys()) {
                LOG.tracef("  Key: kid=%s, kty=%s, alg=%s", key.getKeyId(), key.getKeyType(), key.getAlgorithm());
            }
        }

        Optional<java.time.Duration> tokenAge = vpConfig.getValue().token().age();
        LOG.debugf("Token age configured: %s, expiration enforcement: %s",
                tokenAge.map(Object::toString).orElse("not set"),
                tokenAge.isEmpty() ? "enabled" : "disabled (using token age)");

        CredentialJwtVerifier verifier = new CredentialJwtVerifier(jwks, tokenAge);

        return new Supplier<CredentialJwtVerifier>() {
            @Override
            public CredentialJwtVerifier get() {
                return verifier;
            }
        };
    }

    private static String removeTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
