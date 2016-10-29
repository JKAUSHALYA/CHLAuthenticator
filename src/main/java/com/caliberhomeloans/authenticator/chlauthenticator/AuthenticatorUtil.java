package com.caliberhomeloans.authenticator.chlauthenticator;

import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

/**
 * Utility class for authenticator.
 */
class AuthenticatorUtil {

    /**
     * Get the claim mapping with the remote claim URI.
     * @param remoteClaimUri Remote claim URI.
     * @return ClaimMapping.
     */
    static ClaimMapping getClaimMapping(String remoteClaimUri) {

        Claim remoteClaim = new Claim();
        remoteClaim.setClaimUri(remoteClaimUri);

        ClaimMapping mapping = new ClaimMapping();
        mapping.setRemoteClaim(remoteClaim);

        return mapping;
    }
}
