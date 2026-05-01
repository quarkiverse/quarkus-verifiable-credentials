package io.quarkiverse.oidvp.deployment;

import java.util.function.BooleanSupplier;

import io.quarkiverse.oidvp.runtime.VerifiablePresentationAuthenticationMechanism;
import io.quarkiverse.oidvp.runtime.VerifiablePresentationsProducer;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;

@BuildSteps(onlyIf = OpenIdVerifiablePresentationsBuildStep.IsEnabled.class)
public class OpenIdVerifiablePresentationsBuildStep {

    @BuildStep
    public void additionalBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable();

        builder.addBeanClass(VerifiablePresentationAuthenticationMechanism.class);
        builder.addBeanClass(VerifiablePresentationsProducer.class);
        additionalBeans.produce(builder.build());
    }

    @BuildStep
    ExtensionSslNativeSupportBuildItem enableSslInNative() {
        return new ExtensionSslNativeSupportBuildItem(Feature.OIDC);
    }

    public static class IsEnabled implements BooleanSupplier {
        OpenIdVerifiablePresentationsBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
