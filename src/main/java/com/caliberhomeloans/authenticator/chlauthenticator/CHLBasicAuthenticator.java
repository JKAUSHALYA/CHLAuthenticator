package com.caliberhomeloans.authenticator.chlauthenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is the basic authenticator for the Caliber Home Loans.
 */
public class CHLBasicAuthenticator extends BasicAuthenticator {

    private static final Log log = LogFactory.getLog(CHLBasicAuthenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(CHLAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(CHLAuthenticatorConstants.PASSWORD);

        try {
            String apiUrl = this.getAuthenticatorConfig().getParameterMap().get(CHLAuthenticatorConstants.API_URL);
            if (apiUrl == null || "".equals(apiUrl)) {
                throw new RuntimeException("API URL is missing in the authenticator config.");
            }

            CHLRESTAPIHelper chlRestApiHelper = new CHLRESTAPIHelper(apiUrl);
            String userId = chlRestApiHelper.authenticateUser(username, password);

            if (userId == null) {
                throw new AuthenticationFailedException("No user id present in the response.");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to call the authentication REST endpoint.");
        }

        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        String rememberMe = request.getParameter("chkRemember");

        if (rememberMe != null && "on".equals(rememberMe)) {
            context.setRememberMe(true);
        }
    }

    @Override
    public String getFriendlyName() {
        return CHLAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return CHLAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
