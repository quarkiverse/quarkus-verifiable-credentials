package io.quarkiverse.oidvp.runtime;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

import io.quarkiverse.oidvp.VerifiablePresentations;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class VerifiablePresentationsProducer {

    @Inject
    RoutingContext routingContext;

    @Produces
    @RequestScoped
    public VerifiablePresentations produce() {
        VerifiablePresentations vp = routingContext.get(
                VerifiablePresentationAuthenticationMechanism.VERIFIABLE_PRESENTATIONS_KEY);
        return vp != null ? vp : new VerifiablePresentations();
    }
}
