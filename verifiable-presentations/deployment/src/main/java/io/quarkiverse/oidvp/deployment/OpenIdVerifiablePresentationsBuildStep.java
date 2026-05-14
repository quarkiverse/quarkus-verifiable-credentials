package io.quarkiverse.oidvp.deployment;

import java.util.function.BooleanSupplier;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.jandex.DotName;

import io.quarkiverse.oidvc.deployment.CredentialIssuerMetadataBuildItem;
import io.quarkiverse.oidvp.runtime.CredentialJwtVerifier;
import io.quarkiverse.oidvp.runtime.CredentialJwtVerifierRecorder;
import io.quarkiverse.oidvp.runtime.VerifiablePresentationAuthenticationMechanism;
import io.quarkiverse.oidvp.runtime.VerifiablePresentationsProducer;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.proxy.deployment.ProxyRegistryBuildItem;
import io.quarkus.tls.deployment.spi.TlsRegistryBuildItem;
import io.quarkus.vertx.core.deployment.CoreVertxBuildItem;

@BuildSteps(onlyIf = OpenIdVerifiablePresentationsBuildStep.IsEnabled.class)
public class OpenIdVerifiablePresentationsBuildStep {

    private static final String FEATURE = "verifiable-presentations";
    private static final DotName CREDENTIAL_JWT_VERIFIER = DotName.createSimple(CredentialJwtVerifier.class.getName());

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    public void additionalBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable();

        builder.addBeanClass(VerifiablePresentationAuthenticationMechanism.class);
        builder.addBeanClass(VerifiablePresentationsProducer.class);
        additionalBeans.produce(builder.build());
    }

    @BuildStep
    ExtensionSslNativeSupportBuildItem enableSslInNative() {
        return new ExtensionSslNativeSupportBuildItem(FEATURE);
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    public void generateCredentialJwtVerifier(
            CredentialJwtVerifierRecorder recorder,
            BuildProducer<SyntheticBeanBuildItem> beanProducer,
            CoreVertxBuildItem vertxBuildItem,
            TlsRegistryBuildItem tlsRegistryBuildItem,
            ProxyRegistryBuildItem proxyRegistryBuildItem,
            CredentialIssuerMetadataBuildItem credentialIssuerMetadataBuildItem) {
        beanProducer.produce(SyntheticBeanBuildItem
                .configure(CREDENTIAL_JWT_VERIFIER)
                .setRuntimeInit()
                .defaultBean()
                .scope(ApplicationScoped.class)
                .supplier(recorder.setup(vertxBuildItem.getVertx(), tlsRegistryBuildItem.registry(),
                        proxyRegistryBuildItem.registry(), credentialIssuerMetadataBuildItem.getSupplier()))
                .done());
    }

    public static class IsEnabled implements BooleanSupplier {
        OpenIdVerifiablePresentationsBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
