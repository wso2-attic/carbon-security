/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.caas.internal;

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.caching.CarbonCachingService;
import org.wso2.carbon.identity.mgt.AuthorizationService;
import org.wso2.carbon.identity.mgt.RealmService;
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;

import java.util.Map;

/**
 * OSGi service component which handle authentication and authorization.
 *
 * @since 1.0.0
 */
@Component(
        name = "org.wso2.carbon.security.caas.internal.CarbonSecurityComponent",
        immediate = true,
        property = {
                "componentName=wso2-caas"
        }
)
public class CarbonSecurityComponent implements RequiredCapabilityListener {

    private static final Logger log = LoggerFactory.getLogger(CarbonSecurityComponent.class);

    private ServiceRegistration authorizationServiceRegistration;

    @Activate
    public void registerCarbonSecurityProvider(BundleContext bundleContext) {

        CarbonSecurityDataHolder.getInstance().setBundleContext(bundleContext);

    }

    @Deactivate
    public void unregisterCarbonSecurityProvider(BundleContext bundleContext) {

        try {
            bundleContext.ungetService(authorizationServiceRegistration.getReference());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        log.info("Carbon-Security bundle deactivated successfully.");
    }


    @Reference(
            name = "RealmService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        CarbonSecurityDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        CarbonSecurityDataHolder.getInstance().setRealmService(null);
    }


    @Reference(
            name = "AuthorizationService",
            service = AuthorizationService.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthorizationService"
    )
    protected void setAuthorizationService(AuthorizationService authorizationService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Authorization Service");
        }
        CarbonSecurityDataHolder.getInstance().setAuthorizationService(authorizationService);
    }

    protected void unsetAuthorizationService(AuthorizationService authorizationService) {
        log.debug("UnSetting the Authorization Service");
        CarbonSecurityDataHolder.getInstance().setAuthorizationService(null);
    }

    @Reference(
            name = "carbon.caching.service",
            service = CarbonCachingService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unRegisterCachingService"
    )
    protected void registerCachingService(CarbonCachingService cachingService, Map<String, ?> properties) {
        CarbonSecurityDataHolder.getInstance().registerCacheService(cachingService);
    }

    protected void unRegisterCachingService(CarbonCachingService carbonCachingService) {
        CarbonSecurityDataHolder.getInstance().registerCacheService(null);
    }


    @Override
    public void onAllRequiredCapabilitiesAvailable() {
        log.info("Carbon-Security bundle activated successfully.");
    }
}

