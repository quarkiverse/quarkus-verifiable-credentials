package io.quarkiverse.oidvp;

import com.authlete.sd.SDJWT;

public record VerifiablePresentation(SDJWT sdjwt, String sub, String vct) {
}
