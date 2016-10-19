package com.caliberhomeloans.authenticator.chlauthenticator.internal;

import com.caliberhomeloans.authenticator.chlauthenticator.BasicCustomAuthenticator;
import com.caliberhomeloans.authenticator.chlauthenticator.CHLAuthenticator;
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

    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);

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

        // Register CHLAuthenticatorComponent as an OSGi Service
        context.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                new CHLAuthenticator(), null);
        context.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                new BasicCustomAuthenticator(), null);

        log.info("CHLAuthenticatorComponent bundle is activated");
    }

    protected void deactivate(ComponentContext context) {

        log.info("CHLAuthenticatorComponent bundle is deactivated");
    }
}
