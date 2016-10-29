package com.caliberhomeloans.authenticator.chlauthenticator.internal;

import com.caliberhomeloans.authenticator.chlauthenticator.CHLFederatedBasicAuthenticator;
import com.caliberhomeloans.authenticator.chlauthenticator.CHLFederatedClaimAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="com.caliberhomeloans.authenticator.chlauthenticator.internal" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class CHLAuthenticatorComponent {

    private static final Log log = LogFactory.getLog(CHLAuthenticatorComponent.class);

    private static RealmService realmService;

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void setRealmService(RealmService realmService) {
        CHLAuthenticatorComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        CHLAuthenticatorComponent.realmService = null;
    }

    protected void activate(ComponentContext context) {

        // Register CHL authenticators.
        context.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                new CHLFederatedClaimAuthenticator(), null);

        context.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                new CHLFederatedBasicAuthenticator(), null);

        log.info("CHLAuthenticatorComponent bundle is activated");
    }

    protected void deactivate(ComponentContext context) {

        log.info("CHLAuthenticatorComponent bundle is deactivated");
    }
}
