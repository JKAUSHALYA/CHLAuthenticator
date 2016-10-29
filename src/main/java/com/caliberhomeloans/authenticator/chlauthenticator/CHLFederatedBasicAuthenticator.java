package com.caliberhomeloans.authenticator.chlauthenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is the basic authenticator for the Caliber Home Loans.
 */
public class CHLFederatedBasicAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(CHLFederatedBasicAuthenticator.class);

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String showAuthFailureReason = null;
        if (parameterMap != null) {
            showAuthFailureReason = parameterMap.get("showAuthFailureReason");
            if (log.isDebugEnabled()) {
                log.debug("showAuthFailureReason has been set as : " + showAuthFailureReason);
            }
        }

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String retryPage = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
        String queryParams = context.getContextIdIncludedQueryParams();

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            if (context.getProperty("UserTenantDomainMismatch") != null &&
                    (Boolean)context.getProperty("UserTenantDomainMismatch")) {
                retryParam = "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message";
                context.setProperty("UserTenantDomainMismatch", false);
            }

            IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
            IdentityUtil.clearIdentityErrorMsg();

            if (showAuthFailureReason != null && "true".equals(showAuthFailureReason)) {
                if (errorContext != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Identity error message context is not null");
                    }

                    String errorCode = errorContext.getErrorCode();
                    int remainingAttempts = errorContext.getMaximumLoginAttempts() - errorContext
                            .getFailedLoginAttempts();

                    if (log.isDebugEnabled()) {
                        log.debug("errorCode : " + errorCode);
                        log.debug("username : " + request.getParameter(BasicAuthenticatorConstants.USER_NAME));
                        log.debug("remainingAttempts : " + remainingAttempts);
                    }

                    switch (errorCode) {
                        case UserCoreConstants.ErrorCode.INVALID_CREDENTIAL:
                            retryParam = retryParam + BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                    + BasicAuthenticatorConstants.FAILED_USERNAME
                                    + URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                            BasicAuthenticatorConstants.UTF_8)
                                    + "&remainingAttempts=" + remainingAttempts;
                            response.sendRedirect(response.encodeRedirectURL(loginPage
                                    + ("?" + queryParams))
                                    + BasicAuthenticatorConstants.AUTHENTICATORS
                                    + getName() + ":" + BasicAuthenticatorConstants.LOCAL + retryParam);
                            break;

                        case UserCoreConstants.ErrorCode.USER_IS_LOCKED:
                            String redirectURL = retryPage;
                            if (remainingAttempts == 0) {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                        + BasicAuthenticatorConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                                BasicAuthenticatorConstants.UTF_8)
                                        + "&remainingAttempts=0";
                            } else {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                        + BasicAuthenticatorConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                                BasicAuthenticatorConstants.UTF_8);
                            }
                            response.sendRedirect(redirectURL);
                            break;

                        case UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST:
                            retryParam = retryParam + BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                    + BasicAuthenticatorConstants.FAILED_USERNAME
                                    + URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                    BasicAuthenticatorConstants.UTF_8);
                            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                    + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                            BasicAuthenticatorConstants.LOCAL + retryParam);
                            break;

                        case IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE:
                            retryParam = retryParam + BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                    + BasicAuthenticatorConstants.FAILED_USERNAME
                                    + URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                            BasicAuthenticatorConstants.UTF_8);
                            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                    + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                    + BasicAuthenticatorConstants.LOCAL + retryParam);
                            break;
                    }
                } else {
                    response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + BasicAuthenticatorConstants.LOCAL + retryParam);
                }
            } else {
                String errorCode = errorContext != null ? errorContext.getErrorCode() : null;
                if (errorCode != null && errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                    String redirectURL = retryPage;
                    redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                            BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(request.getParameter(
                            BasicAuthenticatorConstants.USER_NAME), BasicAuthenticatorConstants.UTF_8);
                    response.sendRedirect(redirectURL);

                } else {
                    response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + BasicAuthenticatorConstants.LOCAL + retryParam);
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                    (BasicAuthenticatorConstants.USER_NAME)), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);

        String userId;

        try {

            // Get the API URL from UI.
            String apiUrl = context.getAuthenticatorProperties().get(CHLAuthenticatorConstants.API_UI_URL);

            // If the API URL is not provided from the UI, get it from the file.
            if (apiUrl == null || "".equals(apiUrl)) {
                apiUrl = this.getAuthenticatorConfig().getParameterMap().get(CHLAuthenticatorConstants.API_FILE_URL);
            }

            if (apiUrl == null || "".equals(apiUrl)) {
                throw new RuntimeException("API URL is missing in the authenticator config.");
            }

            CHLRESTAPIHelper chlRestApiHelper = new CHLRESTAPIHelper(apiUrl);

            if (log.isDebugEnabled()) {
                log.debug("API URL is set to: " + apiUrl);
            }

            userId = chlRestApiHelper.authenticateUser(username, password);

            if (log.isDebugEnabled()) {
                log.debug("User id is: " + userId);
            }

            // We assume values less than 0 are authentication failures.
            if (userId == null || Integer.parseInt(userId) < 0) {
                throw new InvalidCredentialsException("No user id present in the response.");
            }
        } catch (IOException e) {
            log.error("Error occurred while accessing authentication REST endpoint: " + e.getMessage());
            throw new AuthenticationFailedException("Failed to call the authentication REST endpoint.", e);
        }

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.getUserAttributes().put(AuthenticatorUtil
                .getClaimMapping(CHLAuthenticatorConstants.USER_ID_CLAIM_URI), userId);

        context.setSubject(authenticatedUser);
        String rememberMe = request.getParameter("chkRemember");

        if (rememberMe != null && "on".equals(rememberMe)) {
            context.setRememberMe(true);
        }
    }

    @Override
    public String getFriendlyName() {
        return CHLAuthenticatorConstants.BASIC_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return CHLAuthenticatorConstants.BASIC_AUTHENTICATOR_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        String userName = httpServletRequest.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = httpServletRequest.getParameter(BasicAuthenticatorConstants.PASSWORD);

        return userName != null && password != null;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
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
        property.setDisplayName("Authentication API URL");
        property.setDescription("URL of the authentication REST API");

        configProperties.add(property);

        return configProperties;
    }
}
