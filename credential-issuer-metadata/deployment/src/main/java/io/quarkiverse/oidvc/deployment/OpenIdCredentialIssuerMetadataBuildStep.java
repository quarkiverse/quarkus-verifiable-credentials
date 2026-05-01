package io.quarkiverse.oidvc.deployment;

import java.util.function.BooleanSupplier;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.jandex.DotName;

import io.quarkiverse.oidvc.CredentialIssuerMetadata;
import io.quarkiverse.oidvc.runtime.OpenIdCredentialIssuerMetadataRecorder;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;
import io.quarkus.proxy.deployment.ProxyRegistryBuildItem;
import io.quarkus.tls.deployment.spi.TlsRegistryBuildItem;
import io.quarkus.vertx.core.deployment.CoreVertxBuildItem;

@BuildSteps(onlyIf = OpenIdCredentialIssuerMetadataBuildStep.IsEnabled.class)
public class OpenIdCredentialIssuerMetadataBuildStep {

    private static final DotName CREDENTIAL_ISSUER_METADATA = DotName
            .createSimple(CredentialIssuerMetadata.class.getName());

    @BuildStep
    ExtensionSslNativeSupportBuildItem enableSslInNative() {
        return new ExtensionSslNativeSupportBuildItem(Feature.OIDC);
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    public void generateBean(
            OpenIdCredentialIssuerMetadataRecorder recorder,
            BuildProducer<SyntheticBeanBuildItem> beanProducer,
            CoreVertxBuildItem vertxBuildItem,
            TlsRegistryBuildItem tlsRegistryBuildItem,
            ProxyRegistryBuildItem proxyRegistryBuildItem) {
        beanProducer.produce(SyntheticBeanBuildItem
                .configure(CREDENTIAL_ISSUER_METADATA)
                .setRuntimeInit()
                .defaultBean()
                .scope(ApplicationScoped.class)
                .supplier(recorder.setup(vertxBuildItem.getVertx(), tlsRegistryBuildItem.registry(),
                        proxyRegistryBuildItem.registry()))
                .done());
    }

    public static class IsEnabled implements BooleanSupplier {
        OpenIdCredentialIssuerMetadataBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
