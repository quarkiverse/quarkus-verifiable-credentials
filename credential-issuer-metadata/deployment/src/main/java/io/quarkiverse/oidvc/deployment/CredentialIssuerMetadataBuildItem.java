package io.quarkiverse.oidvc.deployment;

import java.util.function.Supplier;

import io.quarkiverse.oidvc.CredentialIssuerMetadata;
import io.quarkus.builder.item.SimpleBuildItem;

public final class CredentialIssuerMetadataBuildItem extends SimpleBuildItem {

    private final Supplier<CredentialIssuerMetadata> supplier;

    public CredentialIssuerMetadataBuildItem(Supplier<CredentialIssuerMetadata> supplier) {
        this.supplier = supplier;
    }

    public Supplier<CredentialIssuerMetadata> getSupplier() {
        return supplier;
    }
}
