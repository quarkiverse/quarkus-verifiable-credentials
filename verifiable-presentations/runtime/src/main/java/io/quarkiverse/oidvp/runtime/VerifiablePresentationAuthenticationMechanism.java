package io.quarkiverse.oidvp.runtime;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

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
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.UniEmitter;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class VerifiablePresentationAuthenticationMechanism implements HttpAuthenticationMechanism {

    private static final Logger LOG = Logger.getLogger(VerifiablePresentationAuthenticationMechanism.class);

    private final ConcurrentHashMap<String, List<VerifiablePresentation>> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> responseCodeToSessionId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> stateToNonce = new ConcurrentHashMap<>();

    @Inject
    VerifiablePresentationsConfig config;

    @Inject
    CredentialJwtVerifier credentialJwtVerifier;

    static final String VERIFIABLE_PRESENTATIONS_KEY = "vp_presentations";

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        String path = context.request().path();
        HttpMethod method = context.request().method();

        if (path.equals(config.requestCredentialPath())) {
            LOG.debug("Handling credential request, creating authorization URI");
            String state = UUID.randomUUID().toString();
            String nonce = UUID.randomUUID().toString();
            stateToNonce.put(state, nonce);

            String presentationUrl = config.verifierHost() + config.presentationPath();
            String authorizationUri = "response_mode=direct_post"
                    + "&client_id=redirect_uri:" + URLEncoder.encode(presentationUrl, StandardCharsets.UTF_8)
                    + "&response_uri=" + URLEncoder.encode(presentationUrl, StandardCharsets.UTF_8)
                    + "&response_type=vp_token"
                    + "&nonce=" + nonce
                    + "&state=" + state;
            context.put("vp_authorization_uri", authorizationUri);

            return Uni.createFrom().nullItem();
        }

        if (!path.startsWith(config.presentationPath())) {
            return Uni.createFrom().nullItem();
        }

        if (method == HttpMethod.POST && path.equals(config.presentationPath())) {
            LOG.debug("Received VP token POST, processing form data");
            return getFormUrlEncodedData(context).onItem()
                    .transformToUni(requestParams -> authenticateVpToken(context, requestParams));
        }

        if (method == HttpMethod.GET && path.equals(config.presentationPath())) {
            String responseCode = context.request().getParam("response_code");
            if (responseCode != null) {
                LOG.debug("Exchanging response code for session");
                return exchangeResponseCodeForSession(context, responseCode);
            }

            Cookie sessionCookie = context.request().getCookie("vp_session");
            if (sessionCookie != null) {
                LOG.debug("Authenticating with existing session");
                return authenticateWithSession(context, sessionCookie.getValue());
            }
        }

        return Uni.createFrom().nullItem();
    }

    private Uni<SecurityIdentity> authenticateVpToken(RoutingContext context, MultiMap requestParams) {
        String vpToken = requestParams.get("vp_token");
        String state = requestParams.get("state");

        if (vpToken == null || vpToken.isEmpty()) {
            LOG.debug("No vp_token in request parameters");
            return Uni.createFrom().nullItem();
        }

        LOG.debug("Parsing SD-JWT from vp_token");
        SDJWT sdJwt = SDJWT.parse(vpToken);

        LOG.debug("Verifying credential JWT");
        JsonObject credentialClaims;
        try {
            credentialClaims = credentialJwtVerifier.verify(sdJwt.getCredentialJwt());
        } catch (InvalidJwtException ex) {
            LOG.debugf("Credential JWT verification failed: %s", ex.getMessage());
            throw new AuthenticationFailedException(ex.getMessage());
        }

        LOG.debug("Verifying disclosure hashes");
        verifyDisclosureHashes(sdJwt, credentialClaims);

        LOG.debug("Verifying key binding");
        verifyKeyBinding(sdJwt, credentialClaims, state);

        String sub = resolveSubject(credentialClaims, sdJwt);
        String vct = credentialClaims.getString("vct");
        LOG.debugf("VP token verified successfully, sub=%s, vct=%s", sub, vct);

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
            String responseCode) {
        String sessionId = responseCodeToSessionId.remove(responseCode);
        if (sessionId == null) {
            LOG.warn("Invalid or already used response_code");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }

        if (sessions.get(sessionId) == null) {
            LOG.warn("No presentations found for session");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }

        LOG.debug("Response code exchanged for session, redirecting");
        context.response().addCookie(Cookie.cookie("vp_session", sessionId)
                .setPath("/")
                .setHttpOnly(true)
                .setSecure(context.request().isSSL())
                .setMaxAge(300));

        context.response().setStatusCode(HttpResponseStatus.FOUND.code());
        context.response().putHeader("Location", config.presentationPath());
        context.response().end();

        return Uni.createFrom().nullItem();
    }

    private Uni<SecurityIdentity> authenticateWithSession(RoutingContext context, String sessionId) {
        List<VerifiablePresentation> presentations = sessions.remove(sessionId);
        if (presentations == null || presentations.isEmpty()) {
            LOG.warn("No presentations found for session");
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }

        LOG.debugf("Session authenticated with %d presentation(s)", presentations.size());
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

    private void verifyDisclosureHashes(SDJWT sdJwt, JsonObject credentialClaims) {
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
        LOG.debugf("All %d disclosure hash(es) verified", sdJwt.getDisclosures().size());
    }

    private void verifyKeyBinding(SDJWT sdJwt, JsonObject credentialClaims, String state) {
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

        LOG.debug("Verifying key binding JWT signature");
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
        LOG.debug("Key binding JWT signature verified");

        JsonObject bindingClaims = decodeJwtContent(sdJwt.getBindingJwt());

        LOG.debug("Verifying sd_hash claim");
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

        LOG.debug("Verifying nonce claim");
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

        LOG.debug("Verifying audience claim");
        String expectedClientId = "redirect_uri:" + config.verifierHost() + config.presentationPath();
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
        LOG.debug("Key binding verification completed successfully");
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(
                new ChallengeData(HttpResponseStatus.FOUND.code(), "Location", config.homePath()));
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(
                new HttpCredentialTransport(HttpCredentialTransport.Type.POST, config.presentationPath()));
    }

    private static Uni<MultiMap> getFormUrlEncodedData(RoutingContext context) {
        context.request().setExpectMultipart(true);
        return Uni.createFrom().emitter(new Consumer<UniEmitter<? super MultiMap>>() {
            @Override
            public void accept(UniEmitter<? super MultiMap> t) {
                context.request().endHandler(new Handler<Void>() {
                    @Override
                    public void handle(Void event) {
                        t.complete(context.request().formAttributes());
                    }
                });
                context.request().resume();
            }
        });
    }

    private static String resolveSubject(JsonObject credentialClaims, SDJWT sdJwt) {
        String sub = credentialClaims.getString("sub");
        if (sub == null) {
            for (Disclosure disclosure : sdJwt.getDisclosures()) {
                if ("sub".equals(disclosure.getClaimName())) {
                    return (String) disclosure.getClaimValue();
                }
            }
        }
        return sub;
    }

    private static JsonObject decodeJwtContent(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        String json = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        return new JsonObject(json);
    }
}
