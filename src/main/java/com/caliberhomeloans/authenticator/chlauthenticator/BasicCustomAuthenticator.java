/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.caliberhomeloans.authenticator.chlauthenticator;

import com.caliberhomeloans.authenticator.chlauthenticator.internal.CHLAuthenticatorComponent;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.entitlement.EntitlementService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.ldap.ReadWriteLDAPUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathExpressionException;

/**
 * Username Password based Authenticator that authenticates to the primary user store if
 * specified and to a specific UserStore based on the service provider.
 */
public class BasicCustomAuthenticator extends BasicAuthenticator {

    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);

    private static final long serialVersionUID = 3239188918072434774L;

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(CHLAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(CHLAuthenticatorConstants.PASSWORD);

        if (log.isDebugEnabled()) {
            log.debug("context.getServiceProviderName(): " + context.getServiceProviderName());
            log.debug("username from request: " + username);
        }

        boolean isAuthenticated = false;
        ReadWriteLDAPUserStoreManager userStoreManager;
        // Check the authentication
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = CHLAuthenticatorComponent.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (ReadWriteLDAPUserStoreManager) userRealm.getUserStoreManager();
                if (log.isDebugEnabled()) {
                    log.debug("userStoreManager: " + userStoreManager.getRealmConfiguration().getUserStoreClass());
                }

                // get service provider selection policy, and authenticate against returned user stores
                List<String> userStoreNames = null;
                try {
                    EntitlementService entitlementService = new EntitlementService();

                    String xacmlRequest = generateXACMLRequest(context.getServiceProviderName());
                    if (log.isDebugEnabled()) {
                        log.debug("xacmlRequest: " + xacmlRequest);
                    }

                    String xacmlResponse = entitlementService.getDecision(xacmlRequest);
                    if (log.isDebugEnabled()) {
                        log.debug("xacmlResponse: " + xacmlResponse);
                    }
                    userStoreNames = getUserStoreNames(xacmlResponse);
                } catch (Exception e) {
                    log.error("Exception retrieving the service provider selection policy: " + e.getMessage());
                }

                if (userStoreNames != null) {
                    for (String userStoreName : userStoreNames) {
                        log.info("Authenticating " + userStoreName + "/"
                                + MultitenantUtils.getTenantAwareUsername(username));
                        isAuthenticated = userStoreManager.authenticate(userStoreName + "/"
                                + MultitenantUtils.getTenantAwareUsername(username), password);
                        log.info("Authenticated against user store: " + userStoreName + " result: " + isAuthenticated);
                        if (isAuthenticated) break;
                    }
                } else {
                    // If anything goes wrong retrieving the service provider selection policy, just authenticate
                    // against all user stores
                    log.info("Failed to retrieve the service provider selection policy. Proceeding with default " +
                            "authentication.");
                    isAuthenticated = userStoreManager.authenticate(MultitenantUtils.getTenantAwareUsername(username),
                            password);
                }
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " + tenantId);
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }

            throw new InvalidCredentialsException("User authentication failed due to invalid credentials");
        }

        Map<String, Object> authProperties = context.getProperties();
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        // TODO: user tenant domain has to be an attribute in the AuthenticationContext
        authProperties.put("user-tenant-domain", tenantDomain);

        username = FrameworkUtils.prependUserStoreDomainToName(username);
        log.debug("username FrameworkUtils.prependUserStoreDomainToName: " + username);

        if (getAuthenticatorConfig().getParameterMap() != null) {
            String userNameUri = getAuthenticatorConfig().getParameterMap().get("UserNameAttributeClaimUri");
            if (userNameUri != null && userNameUri.trim().length() > 0) {
                boolean multipleAttributeEnable;
                String domain = UserCoreUtil.getDomainFromThreadLocal();
                if (domain != null && domain.trim().length() > 0) {
                    multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.getSecondaryUserStoreManager(domain).
                            getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                } else {
                    multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.
                            getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                }
                if (multipleAttributeEnable) {
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Searching for UserNameAttribute value for user " + username +
                                    " for claim uri : " + userNameUri);
                        }
                        String usernameValue = userStoreManager.
                                getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), userNameUri, null);
                        if (usernameValue != null && usernameValue.trim().length() > 0) {
                            tenantDomain = MultitenantUtils.getTenantDomain(username);
                            usernameValue = FrameworkUtils.prependUserStoreDomainToName(usernameValue);
                            username = usernameValue + "@" + tenantDomain;
                            if (log.isDebugEnabled()) {
                                log.debug("UserNameAttribute is found for user. Value is :  " + username);
                            }
                        }
                    } catch (UserStoreException e) {
                        // ignore  but log in debug
                        if (log.isDebugEnabled()) {
                            log.debug("Error while retrieving UserNameAttribute for user : " + username, e);
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("MultipleAttribute is not enabled for user store domain : " + domain + " " +
                                "Therefore UserNameAttribute is not retrieved");
                    }
                }
            }
        }
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        String rememberMe = request.getParameter("chkRemember");

        if (rememberMe != null && "on".equals(rememberMe)) {
            context.setRememberMe(true);
        }

    }

    private List<String> getUserStoreNames(final String xacmlResponse)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder docbuilder = factory.newDocumentBuilder();

        final Document xacmlResponseDocument = docbuilder.parse(new InputSource(new StringReader(xacmlResponse)));
        xacmlResponseDocument.getDocumentElement().normalize();

        String decision = null;
        final NodeList decisionList = xacmlResponseDocument.getElementsByTagName("Decision");
        if (decisionList != null && decisionList.getLength() > 0) {
            decision = decisionList.item(0).getTextContent();
        }
        if (log.isDebugEnabled()) {
            log.debug("decision: " + decision);
        }

        List<String> userStoreNames = new ArrayList<>();
        if (decision.equalsIgnoreCase("Permit")) {
            final NodeList attributeAssignementList = xacmlResponseDocument.getElementsByTagName("AttributeAssignment");
            if (attributeAssignementList != null && attributeAssignementList.getLength() > 0) {
                for (int i = 0; i < attributeAssignementList.getLength(); i++) {
                    Node attributeAssignement = attributeAssignementList.item(i);
                    NamedNodeMap attributes = attributeAssignement.getAttributes();
                    if (attributes.getNamedItem("AttributeId").getTextContent().equalsIgnoreCase("sp_userstores")) {
                        userStoreNames.add(attributeAssignementList.item(i).getTextContent().trim());
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("userStoreNames: " + userStoreNames);
        }

        return userStoreNames;
    }

    private String generateXACMLRequest(String serviceProvider) throws ParserConfigurationException,
            TransformerException {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = factory.newDocumentBuilder();
        Document document = documentBuilder.newDocument();

        // Request
        Element mainRootElement = document.createElementNS("urn:oasis:names:tc:xacml:3.0:core:schema:wd-17", "Request");
        mainRootElement.setAttribute("CombinedDecision", "false");
        mainRootElement.setAttribute("ReturnPolicyIdList", "false");

        // Attributes
        Element attributes = document.createElement("Attributes");
        attributes.setAttribute("Category", "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");

        // Attribute
        Element attribute = document.createElement("Attribute");
        attribute.setAttribute("AttributeId", "urn:oasis:names:tc:xacml:1.0:subject:subject-id");
        attribute.setAttribute("IncludeInResult", "false");

        // AttributeValue
        Element attributeValue = document.createElement("AttributeValue");
        attributeValue.setAttribute("DataType", "http://www.w3.org/2001/XMLSchema#string");
        attributeValue.setTextContent(serviceProvider);

        attribute.appendChild(attributeValue);
        attributes.appendChild(attribute);
        mainRootElement.appendChild(attributes);
        document.appendChild(mainRootElement);

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        DOMSource source = new DOMSource(document);

        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        transformer.transform(source, result);

        return writer.toString();
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