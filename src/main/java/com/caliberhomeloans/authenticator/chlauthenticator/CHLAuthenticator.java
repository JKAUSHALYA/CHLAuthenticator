package com.caliberhomeloans.authenticator.chlauthenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Custom authenticator to pick the user store from user and validate it against the SP user stores.
 */
public class CHLAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {

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

        if (authenticatedUser == null){
            throw new AuthenticationFailedException("Could not locate an authenticated username from previous steps.");
        }

        if (authenticatedUser.getUserStoreDomain() == null) {
            authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        }

        List<String> userStores = getUserStoresForSP("");

        if (!userStores.contains(authenticatedUser.getUserStoreDomain())) {
            throw new AuthenticationFailedException("Error");
        }

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
    public String getName() {
        return "CHLAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "CHL Authenticator";
    }

    private List<String> getUserStoresForSP(String serviceProvider) {

        List<String> userStores = new ArrayList<>();
        userStores.add("PRIMARY");

        return userStores;
    }
}
