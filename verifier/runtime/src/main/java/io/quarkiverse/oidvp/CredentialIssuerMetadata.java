package io.quarkiverse.oidvp;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public class CredentialIssuerMetadata {
    public static final String CREDENTIAL_ISSUER = "credential_issuer";
    public static final String CREDENTIAL_ENDPOINT = "credential_endpoint";
    public static final String DEFERRED_CREDENTIAL_ENDPOINT = "deferred_credential_endpoint";
    public static final String NONCE_ENDPOINT = "nonce_endpoint";
    public static final String AUTHORIZATION_SERVERS = "authorization_servers";
    public static final String CREDENTIALS_CONFIGURATIONS_SUPPORTED = "credential_configurations_supported";

    private final URI authServerUrl;
    private final JsonObject metadata;

    public CredentialIssuerMetadata(String authServerUrl, JsonObject metadata) {
        this.authServerUrl = URI.create(authServerUrl);
        this.metadata = metadata;
    }

    public String getAuthServerUrl() {
        return authServerUrl.toString();
    }

    public JsonObject getMetadata() {
        return metadata;
    }

    public String getCredentialIssuer() {
        return updateHost(metadata.getString(CREDENTIAL_ISSUER));
    }

    public String getCredentialEndpoint() {
        return updateHost(metadata.getString(CREDENTIAL_ENDPOINT));
    }

    public String getDeferredCredentialEndpoint() {
        return updateHost(metadata.getString(DEFERRED_CREDENTIAL_ENDPOINT));
    }

    public String getNonceEndpoint() {
        return updateHost(metadata.getString(NONCE_ENDPOINT));
    }

    public List<String> getAuthorizationServer() {
        return getStringList(AUTHORIZATION_SERVERS);
    }

    public Map<String, CredentialConfiguration> getCredentialConfigurations() {
        JsonObject allCreds = metadata.getJsonObject(CREDENTIALS_CONFIGURATIONS_SUPPORTED);
        Map<String, CredentialConfiguration> credentials = new HashMap<String, CredentialConfiguration>(
                allCreds.fieldNames().size());

        for (String credName : allCreds.fieldNames()) {
            JsonObject credJson = allCreds.getJsonObject(credName);
            JsonObject credMetadata = credJson.getJsonObject("credential_metadata");
            String displayName = null;
            String displayLogoUri = null;
            String type = null;
            if (credMetadata != null) {
                JsonArray displayArray = credMetadata.getJsonArray("display");
                if (displayArray != null && !displayArray.isEmpty()) {
                    JsonObject display = displayArray.getJsonObject(0);
                    displayName = display.getString("name");
                    JsonObject logo = display.getJsonObject("logo");
                    if (logo != null) {
                        displayLogoUri = logo.getString("uri");
                    }
                }
            }

            JsonObject credDefinition = credJson.getJsonObject("credential_definition");
            if (credDefinition != null) {
                JsonArray typeArray = credDefinition.getJsonArray("type");
                if (typeArray != null && !typeArray.isEmpty()) {
                    type = typeArray.getString(0);
                }
            }

            credentials.put(credJson.getString("id"), new CredentialConfiguration(
                    credJson.getString("id"),
                    credJson.getString("format"),
                    credJson.getString("scope"),
                    displayName,
                    displayLogoUri,
                    type));
        }

        return credentials;
    }

    public String get(String propertyName) {
        return metadata.getString(propertyName);
    }

    public List<String> getStringList(String propertyName) {
        JsonArray array = metadata.getJsonArray(propertyName);
        if (array != null) {
            @SuppressWarnings("unchecked")
            List<String> values = array.getList();
            return Collections.unmodifiableList(values);
        } else {
            return null;
        }
    }

    public boolean contains(String propertyName) {
        return metadata.containsKey(propertyName);
    }

    public Set<String> getPropertyNames() {
        return Collections.unmodifiableSet(metadata.fieldNames());
    }

    public static record CredentialConfiguration(String id, String format, String scope, String displayName,
            String displayLogoUri, String type) {
    }

    private String updateHost(String uri) {
        // Temporary workaround around the NGrok and localhost domains
        if (uri.startsWith("https://" + authServerUrl.getHost())) {
            return uri;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("https://" + authServerUrl.getHost());
        sb.append(authServerUrl.getRawPath());
        return sb.toString();
    }
}
