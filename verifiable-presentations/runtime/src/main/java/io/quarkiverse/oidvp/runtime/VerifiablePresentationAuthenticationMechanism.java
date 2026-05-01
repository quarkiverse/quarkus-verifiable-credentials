package io.quarkiverse.oidvp.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.oidvp.VerifiablePresentation;
import io.quarkiverse.oidvp.VerifiablePresentations;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.runtime.OidcProvider;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.quarkus.oidc.runtime.TenantConfigContext;
import io.quarkus.oidc.runtime.TokenVerificationResult;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.smallrye.mutiny.Uni;
import io.vertx.core.MultiMap;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class VerifiablePresentationAuthenticationMechanism implements HttpAuthenticationMechanism {

    private static final Logger LOG = Logger.getLogger(VerifiablePresentationAuthenticationMechanism.class);
    private static final String REQUEST_CREDENTIAL_PATH = "/best-software-company/request-credential";
    private static final String PRESENTATION_PATH = "/best-software-company/presentation";
    private static final String HOME_PATH = "/best-software-company";

    private final ConcurrentHashMap<String, List<VerifiablePresentation>> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> responseCodeToSessionId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> stateToNonce = new ConcurrentHashMap<>();

    @ConfigProperty(name = "verifier.host")
    String verifierHost;

    @Inject
    TenantConfigBean tenantConfigBean;

    static final String VERIFIABLE_PRESENTATIONS_KEY = "vp_presentations";

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        if (context.request().path().equals(REQUEST_CREDENTIAL_PATH)) {
            String state = UUID.randomUUID().toString();
            String nonce = UUID.randomUUID().toString();
            stateToNonce.put(state, nonce);

            String presentationUrl = verifierHost + PRESENTATION_PATH;
            String authorizationUri = "response_mode=direct_post"
                    + "&client_id=redirect_uri:" + OidcCommonUtils.urlEncode(presentationUrl)
                    + "&response_uri=" + OidcCommonUtils.urlEncode(presentationUrl)
                    + "&response_type=vp_token"
                    + "&nonce=" + nonce
                    + "&state=" + state;
            context.put("vp_authorization_uri", authorizationUri);

            context.response().addCookie(Cookie.cookie("vp_state", state)
                    .setPath("/")
                    .setHttpOnly(true)
                    //.setSecure(true)
                    .setMaxAge(300));
            return Uni.createFrom().nullItem();
        }

        if (!context.request().path().startsWith(PRESENTATION_PATH)) {
            return Uni.createFrom().nullItem();
        }

        if (context.request().method() == HttpMethod.POST && context.request().path().equals(PRESENTATION_PATH)) {
            return OidcUtils.getFormUrlEncodedData(context).onItem()
                    .transformToUni(requestParams -> authenticateVpToken(context, requestParams));
        }

        if (context.request().method() == HttpMethod.GET && context.request().path().equals(PRESENTATION_PATH)) {
            String responseCode = context.request().getParam("response_code");
            Cookie stateCookie = context.request().getCookie("vp_state");
            if (responseCode != null && stateCookie != null) {
                return exchangeResponseCodeForSession(context, responseCode, stateCookie.getValue());
            }

            Cookie sessionCookie = context.request().getCookie("vp_session");
            if (sessionCookie != null) {
                return authenticateWithSession(context, sessionCookie.getValue());
            }
        }

        return Uni.createFrom().nullItem();
    }

    private Uni<SecurityIdentity> authenticateVpToken(RoutingContext context, MultiMap requestParams) {
        String vpToken = requestParams.get("vp_token");
        String state = requestParams.get("state");

        if (vpToken == null || vpToken.isEmpty()) {
            return Uni.createFrom().nullItem();
        }

        Cookie stateCookie = context.request().getCookie("vp_state");
        if (stateCookie == null) {
            LOG.warn("State cookie is missing");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }
        if (!stateCookie.getValue().equals(state)) {
            LOG.warn("State cookie does not match the presentation state");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }
        SDJWT sdJwt = SDJWT.parse(vpToken);

        TenantConfigContext configContext = tenantConfigBean.getDefaultTenant();
        TokenVerificationResult credentialJwtResult = verifyCredentialJwt(
                configContext.provider(), configContext.getOidcTenantConfig(), sdJwt.getCredentialJwt());

        verifyDisclosureHashes(sdJwt, credentialJwtResult);
        verifyKeyBinding(sdJwt, credentialJwtResult, state);

        JsonObject credentialClaims = credentialJwtResult.localVerificationResult();
        String sub = credentialClaims.getString("sub");
        String vct = credentialClaims.getString("vct");

        VerifiablePresentation vp = new VerifiablePresentation(sdJwt, sub, vct);

        String sessionId = createSession(vp);
        String responseCode = UUID.randomUUID().toString();
        responseCodeToSessionId.put(responseCode, sessionId);
        context.put("vp_response_code", responseCode);

        SecurityIdentity identity = QuarkusSecurityIdentity.builder()
                .setPrincipal(() -> sub)
                .addAttribute("credential", sdJwt.getCredentialJwt())
                .addAttribute("sdjwt", sdJwt)
                .addAttribute("vct", vct)
                .build();

        return Uni.createFrom().item(identity);
    }

    private Uni<SecurityIdentity> exchangeResponseCodeForSession(RoutingContext context,
            String responseCode, String transactionId) {
        String sessionId = responseCodeToSessionId.remove(responseCode);
        if (sessionId == null) {
            LOG.warn("Invalid or already used response_code");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }

        if (sessions.get(sessionId) == null) {
            LOG.warn("No presentations found for session");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }

        context.response().removeCookie("vp_state");
        context.response().addCookie(Cookie.cookie("vp_session", sessionId)
                .setPath("/")
                .setHttpOnly(true)
                //.setSecure(true)
                .setMaxAge(300));

        context.response().setStatusCode(HttpResponseStatus.FOUND.code());
        context.response().putHeader("Location", PRESENTATION_PATH);
        context.response().end();

        return Uni.createFrom().nullItem();
    }

    private Uni<SecurityIdentity> authenticateWithSession(RoutingContext context, String sessionId) {
        List<VerifiablePresentation> presentations = sessions.remove(sessionId);
        if (presentations == null || presentations.isEmpty()) {
            LOG.warn("No presentations found for session");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }

        context.response().removeCookie("vp_session");

        VerifiablePresentations verifiablePresentations = new VerifiablePresentations();
        VerifiablePresentation first = presentations.get(0);
        for (VerifiablePresentation vp : presentations) {
            verifiablePresentations.add(vp);
        }
        context.put(VERIFIABLE_PRESENTATIONS_KEY, verifiablePresentations);

        SecurityIdentity identity = QuarkusSecurityIdentity.builder()
                .setPrincipal(() -> first.sub())
                .addAttribute("sdjwt", first.sdjwt())
                .addAttribute("vct", first.vct())
                .build();

        return Uni.createFrom().item(identity);
    }

    public String createSession(VerifiablePresentation presentation) {
        String sessionId = UUID.randomUUID().toString();
        List<VerifiablePresentation> list = new ArrayList<>();
        list.add(presentation);
        sessions.put(sessionId, list);
        return sessionId;
    }

    private void verifyDisclosureHashes(SDJWT sdJwt, TokenVerificationResult credentialJwtResult) {
        JsonObject credentialClaims = credentialJwtResult.localVerificationResult();
        JsonArray sdArray = credentialClaims.getJsonArray("_sd");
        if (sdArray == null) {
            LOG.warn("Credential JWT does not contain _sd array");
            throw new AuthenticationFailedException();
        }
        for (Disclosure disclosure : sdJwt.getDisclosures()) {
            if (!sdArray.contains(disclosure.digest())) {
                LOG.warnf("Disclosure digest %s not found in credential JWT _sd array", disclosure.digest());
                throw new AuthenticationFailedException();
            }
        }
    }

    private void verifyKeyBinding(SDJWT sdJwt, TokenVerificationResult credentialJwtResult, String state) {
        JsonObject credentialClaims = credentialJwtResult.localVerificationResult();

        JsonObject cnf = credentialClaims.getJsonObject("cnf");
        if (cnf == null) {
            LOG.warn("Confirmation is missing");
            throw new AuthenticationFailedException();
        }
        JsonObject jwkProof = cnf.getJsonObject("jwk");
        if (jwkProof == null) {
            LOG.warn("JWK proof is missing");
            throw new AuthenticationFailedException();
        }

        PublicJsonWebKey publicJsonWebKey;
        try {
            publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(jwkProof.getMap());
        } catch (JoseException ex) {
            LOG.warn("JWK proof does not represent a valid JWK key");
            throw new AuthenticationFailedException();
        }

        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, "ES256"));
            jws.setCompactSerialization(sdJwt.getBindingJwt());
            jws.setKey(publicJsonWebKey.getPublicKey());
            if (!jws.verifySignature()) {
                LOG.warn("Key binding token signature is invalid");
                throw new AuthenticationFailedException();
            }
        } catch (JoseException ex) {
            LOG.warn("Key binding token signature can not be verified");
            throw new AuthenticationFailedException();
        }

        JsonObject bindingClaims = OidcUtils.decodeJwtContent(sdJwt.getBindingJwt());
        String sdHashClaim = bindingClaims.getString("sd_hash");
        if (sdHashClaim == null) {
            LOG.warn("Key binding JWT does not contain sd_hash claim");
            throw new AuthenticationFailedException();
        }
        String expectedSdHash = sdJwt.getSDHash();
        if (!sdHashClaim.equals(expectedSdHash)) {
            LOG.warn("Key binding JWT sd_hash does not match the SD-JWT hash");
            throw new AuthenticationFailedException();
        }

        String expectedNonce = stateToNonce.remove(state);
        if (expectedNonce == null) {
            LOG.warn("No nonce registered for the given state");
            throw new AuthenticationFailedException();
        }
        String nonceClaim = bindingClaims.getString("nonce");
        if (!expectedNonce.equals(nonceClaim)) {
            LOG.warn("Key binding JWT nonce does not match the expected nonce");
            throw new AuthenticationFailedException();
        }

        String expectedClientId = "redirect_uri:" + verifierHost + PRESENTATION_PATH;
        Object audClaim = bindingClaims.getValue("aud");
        boolean audValid = false;
        if (audClaim instanceof String audString) {
            audValid = expectedClientId.equals(audString);
        } else if (audClaim instanceof JsonArray audArray) {
            audValid = audArray.contains(expectedClientId);
        }
        if (!audValid) {
            LOG.warn("Key binding JWT aud does not match the expected client_id");
            throw new AuthenticationFailedException();
        }
    }

    private static TokenVerificationResult verifyCredentialJwt(OidcProvider provider, OidcTenantConfig oidcConfig,
            String credentialJwt) {
        try {
            final boolean enforceExpClaim = oidcConfig.token().age().isEmpty();
            return provider.verifyJwtToken(credentialJwt, false, false, null, enforceExpClaim);
        } catch (InvalidJwtException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(
                new ChallengeData(HttpResponseStatus.FOUND.code(), "Location", HOME_PATH));
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(
                new HttpCredentialTransport(HttpCredentialTransport.Type.POST, PRESENTATION_PATH));
    }
}
