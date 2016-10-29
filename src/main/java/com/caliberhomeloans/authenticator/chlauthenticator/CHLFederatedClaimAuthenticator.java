package com.caliberhomeloans.authenticator.chlauthenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Custom authenticator to retrieve custom claims from the CHL authenticator.
 */
public class CHLFederatedClaimAuthenticator extends AbstractApplicationAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(CHLFederatedClaimAuthenticator.class);

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        // We don't need to handle logout requests from here.
        if (!authenticationContext.isLogoutRequest()) {
            processAuthenticationResponse(httpServletRequest, httpServletResponse, authenticationContext);
        }

        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        // Get the authenticated user from the previous step.
        AuthenticatedUser authenticatedUser = null;
        for (StepConfig stepConfig : authenticationContext.getSequenceConfig().getStepMap().values()) {
            if (stepConfig.getAuthenticatedUser() != null) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Could not locate an authenticated user from previous steps.");
        }

        // Get the API url from UI.
        String apiUrl = authenticationContext.getAuthenticatorProperties().get(CHLAuthenticatorConstants.API_UI_URL);

        // If the API url is not available in the UI, get it from the file.
        if (apiUrl == null || "".equals(apiUrl)) {
            apiUrl = this.getAuthenticatorConfig().getParameterMap().get(CHLAuthenticatorConstants.API_FILE_URL);
        }

        if (log.isDebugEnabled()) {
            log.debug("API URL is set to: " + apiUrl);
        }

        CHLRESTAPIHelper chlRestApiHelper = new CHLRESTAPIHelper(apiUrl);

        JSONObject userIdClaims;
        try {
            userIdClaims = chlRestApiHelper.getUserIdAppNameClaims(authenticatedUser.getUserName(),
                    authenticatedUser.getUserAttributes().get(AuthenticatorUtil
                            .getClaimMapping(CHLAuthenticatorConstants.USER_ID_CLAIM_URI)),
                    authenticationContext.getServiceProviderName());
        } catch (IOException e) {
            log.error("An error occurred while accessing the claims REST endpoint: " + e.getMessage());
            throw new AuthenticationFailedException("Failed to call the authentication REST endpoint.", e);
        }

        authenticatedUser.getUserAttributes().put(AuthenticatorUtil.getClaimMapping(
                CHLAuthenticatorConstants.USER_ID_APP_NAME_CLAIM_URI), userIdClaims.toString());

        authenticationContext.setSubject(authenticatedUser);
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property property = new Property();
        property.setName(CHLAuthenticatorConstants.API_UI_URL);
        property.setDisplayName("Claim API URL");
        property.setDescription("URL to retrieve custom claims.");

        configProperties.add(property);

        return configProperties;
    }

    @Override
    public String getName() {
        return CHLAuthenticatorConstants.CLAIM_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return CHLAuthenticatorConstants.CLAIM_AUTHENTICATOR_FRIENDLY_NAME;
    }
}
