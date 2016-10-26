package com.caliberhomeloans.authenticator.chlauthenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Custom authenticator to retrieve custom claims.
 */
public class CHLCustomClaimAuthenticator extends AbstractApplicationAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = null;
        for (StepConfig stepConfig : authenticationContext.getSequenceConfig().getStepMap().values()) {
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Could not locate an authenticated user from previous steps.");
        }

        if (authenticatedUser.getUserStoreDomain() == null) {
            authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        }

        String url = this.getAuthenticatorConfig().getParameterMap().get(CHLAuthenticatorConstants.API_URL);
        CHLRESTAPIHelper chlrestapiHelper = new CHLRESTAPIHelper(url);

        JSONObject userIdClaims;
        try {
            userIdClaims = chlrestapiHelper.getUserIdAppNameClaims(authenticatedUser.getUserName(),
                    authenticationContext.getServiceProviderName());
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to call the authentication REST endpoint.");
        }

        authenticatedUser.getUserAttributes().put(getClaimMapping(
                CHLAuthenticatorConstants.USER_ID_APP_NAME_CLAIM_URI), userIdClaims.toString());

        authenticationContext.setSubject(authenticatedUser);
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        // TODO: Handle the logic here.
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    @Override
    public String getName() {
        return "CHLCustomClaimAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "CHL Custom Claim Authenticator";
    }

    private ClaimMapping getClaimMapping(String uri) {

        Claim localClaim = new Claim();
        localClaim.setClaimUri(uri);

        Claim remoteClaim = new Claim();
        remoteClaim.setClaimUri(uri);

        ClaimMapping mapping = new ClaimMapping();
        mapping.setLocalClaim(localClaim);
        mapping.setRemoteClaim(remoteClaim);

        return mapping;
    }
}
