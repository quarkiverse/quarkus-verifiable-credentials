package io.quarkiverse.oidvp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VerifiablePresentations {

    private final List<VerifiablePresentation> presentations = new ArrayList<>();

    public void add(VerifiablePresentation presentation) {
        presentations.add(presentation);
    }

    public List<VerifiablePresentation> getAll() {
        return Collections.unmodifiableList(presentations);
    }
}
