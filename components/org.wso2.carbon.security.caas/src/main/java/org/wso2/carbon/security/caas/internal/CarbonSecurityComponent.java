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
import org.osgi.service.permissionadmin.PermissionAdmin;
import org.osgi.service.permissionadmin.PermissionInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.caching.CarbonCachingService;
import org.wso2.carbon.identity.mgt.RealmService;
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;
import org.wso2.carbon.security.caas.api.CarbonJAASConfiguration;
import org.wso2.carbon.security.caas.api.CarbonPolicy;
import org.wso2.carbon.security.caas.boot.ProxyLoginModule;
import org.wso2.carbon.security.caas.internal.config.DefaultPermissionInfo;
import org.wso2.carbon.security.caas.internal.config.DefaultPermissionInfoCollection;
import org.wso2.carbon.security.caas.internal.config.SecurityConfigBuilder;
import org.wso2.carbon.security.caas.internal.config.StoreConfigBuilder;
import org.wso2.carbon.security.caas.user.core.common.CarbonAuthorizationServiceImpl;
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.service.AuthorizationService;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;

import java.security.Policy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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

    private ServiceRegistration realmServiceRegistration;

    @Activate
    public void registerCarbonSecurityProvider(BundleContext bundleContext) {

        CarbonSecurityDataHolder.getInstance().setBundleContext(bundleContext);
        initAuthenticationConfigs(bundleContext);
    }

    @Deactivate
    public void unregisterCarbonSecurityProvider(BundleContext bundleContext) {

        try {
            bundleContext.ungetService(realmServiceRegistration.getReference());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        log.info("Carbon-Security bundle deactivated successfully.");
    }

    @Reference(
            name = "AuthorizationStoreConnectorFactory",
            service = AuthorizationStoreConnectorFactory.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterAuthorizationStoreConnectorFactory"
    )
    protected void registerAuthorizationStoreConnectorFactory(
            AuthorizationStoreConnectorFactory authorizationStoreConnectorFactory, Map<String, String> properties) {

        String connectorId = properties.get("connector-type");
        CarbonSecurityDataHolder.getInstance()
                .registerAuthorizationStoreConnectorFactory(connectorId, authorizationStoreConnectorFactory);
    }

    protected void unregisterAuthorizationStoreConnectorFactory(
            AuthorizationStoreConnectorFactory authorizationStoreConnectorFactory) {
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


    /**
     * Initialize authentication related configs.
     *
     * @param bundleContext
     */
    private void initAuthenticationConfigs(BundleContext bundleContext) {

        // Initialize proxy login module.
        ProxyLoginModule.init(bundleContext);

        // Set CarbonJAASConfiguration as the implementation of Configuration.
        CarbonJAASConfiguration configuration = new CarbonJAASConfiguration();
        configuration.init();
    }

    /**
     * Initialize authorization related configs.
     *
     * @param bundleContext
     */
    private void initAuthorizationConfigs(BundleContext bundleContext) {

        // Set default permissions for all bundles.
        setDefaultPermissions(bundleContext);

        // Registering CarbonPolicy
        CarbonPolicy policy = new CarbonPolicy();
        Policy.setPolicy(policy);
    }

    /**
     * Set default permissions for all bundles using PermissionAdmin.
     *
     * @param context Bundle context.
     */
    private void setDefaultPermissions(BundleContext context) {

        PermissionAdmin permissionAdmin = getPermissionAdmin(context);
        if (permissionAdmin == null) {
            return;
        }

        DefaultPermissionInfoCollection permissionInfoCollection = SecurityConfigBuilder
                .buildDefaultPermissionInfoCollection();
        if (Collections.EMPTY_SET.equals(permissionInfoCollection.getPermissions())) {
            throw new RuntimeException("Default permission info collection can't be empty.");
        }

        List<PermissionInfo> permissionInfoList = new ArrayList<>();

        for (DefaultPermissionInfo permissionInfo : permissionInfoCollection.getPermissions()) {

            if (permissionInfo.getType() == null || permissionInfo.getType().trim().isEmpty()) {
                throw new IllegalArgumentException("Type can't be null or empty.");

            }
            if (permissionInfo.getName() == null || permissionInfo.getName().trim().isEmpty()) {
                throw new IllegalArgumentException("Name can't be null or empty.");
            }

            permissionInfoList.add(new PermissionInfo(permissionInfo.getType(), permissionInfo.getName(),
                    (permissionInfo.getActions() != null && !permissionInfo
                            .getActions().trim().isEmpty()) ?
                            permissionInfo.getActions().trim() : null));
        }

        permissionAdmin.setDefaultPermissions(
                permissionInfoList.toArray(new PermissionInfo[permissionInfoList.size()]));
    }

    /**
     * Get PermissionAdmin.
     *
     * @param context Bundle context.
     * @return Permission admin.
     */
    private PermissionAdmin getPermissionAdmin(BundleContext context) {
        return (PermissionAdmin) context.getService(context.getServiceReference(PermissionAdmin.class.getName()));
    }

    @Override
    public void onAllRequiredCapabilitiesAvailable() {

        BundleContext bundleContext = CarbonSecurityDataHolder.getInstance().getBundleContext();

        // If security manager is enabled init authorization configs
        if (System.getProperty("java.security.manager") != null) {
            initAuthorizationConfigs(bundleContext);
        }

        // Register the carbon realm service.
        try {
            // TODO: Validate the configuration files for multiple primary attributes.
            StoreConfig storeConfig = StoreConfigBuilder.buildStoreConfigs();
            CarbonAuthorizationServiceImpl carbonRealmService = new CarbonAuthorizationServiceImpl(storeConfig);
            CarbonSecurityDataHolder.getInstance().registerCarbonRealmService(carbonRealmService);
            realmServiceRegistration = bundleContext.registerService(AuthorizationService.class.getName(),
                    carbonRealmService, null);
            log.info("Realm service registered successfully.");
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }


        log.info("Carbon-Security bundle activated successfully.");
    }
}

