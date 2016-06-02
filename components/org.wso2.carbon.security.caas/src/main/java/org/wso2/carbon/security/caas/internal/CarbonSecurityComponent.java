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
import org.wso2.carbon.security.caas.api.CarbonCallbackHandler;
import org.wso2.carbon.security.caas.api.CarbonJAASConfiguration;
import org.wso2.carbon.security.caas.api.CarbonPolicy;
import org.wso2.carbon.security.caas.api.module.UsernamePasswordLoginModule;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.boot.ProxyLoginModule;
import org.wso2.carbon.security.caas.internal.config.ClaimConfig;
import org.wso2.carbon.security.caas.internal.config.ClaimConfigBuilder;
import org.wso2.carbon.security.caas.internal.config.DefaultPermissionInfo;
import org.wso2.carbon.security.caas.internal.config.DefaultPermissionInfoCollection;
import org.wso2.carbon.security.caas.internal.config.SecurityConfigBuilder;
import org.wso2.carbon.security.caas.internal.config.StoreConfigBuilder;
import org.wso2.carbon.security.caas.internal.osgi.UserNamePasswordLoginModuleFactory;
import org.wso2.carbon.security.caas.internal.osgi.UsernamePasswordCallbackHandlerFactory;
import org.wso2.carbon.security.caas.user.core.claim.ClaimManager;
import org.wso2.carbon.security.caas.user.core.claim.InMemoryClaimManager;
import org.wso2.carbon.security.caas.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.ClaimManagerException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;

import java.security.Policy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import javax.security.auth.spi.LoginModule;

/**
 * OSGi service component which handle authentication and authorization.
 *
 * @since 1.0.0
 */
@Component(
        name = "org.wso2.carbon.security.caas.internal.CarbonSecurityComponent",
        immediate = true
)
public class CarbonSecurityComponent {

    private static final Logger log = LoggerFactory.getLogger(CarbonSecurityComponent.class);

    private ServiceRegistration realmServiceRegistration;

    @Activate
    public void registerCarbonSecurityProvider(BundleContext bundleContext) {

        initAuthenticationConfigs(bundleContext);

        // if security manager is enabled init authorization configs
        if (System.getProperty("java.security.manager") != null) {
            initAuthorizationConfigs(bundleContext);
        }

        // Register the carbon realm service.
        try {

            StoreConfig storeConfig = StoreConfigBuilder.buildStoreConfigs();
            CarbonRealmServiceImpl carbonRealmService = new CarbonRealmServiceImpl(storeConfig);
            CarbonSecurityDataHolder.getInstance().registerCarbonRealmService(carbonRealmService);
            realmServiceRegistration = bundleContext
                    .registerService(RealmService.class.getName(), carbonRealmService, null);
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }

        ClaimConfig claimConfig = ClaimConfigBuilder.getClaimConfig();
        CarbonSecurityDataHolder.getInstance().setClaimConfig(claimConfig);
        if ("DEFAULT".equals(claimConfig.getClaimManager())) {
            InMemoryClaimManager claimManager = new InMemoryClaimManager();
            try {
                claimManager.init(claimConfig.getClaimMappings());
            } catch (ClaimManagerException e) {
                log.error("Failed to initialze Inmemory Claim Manager", e);
            }
            CarbonSecurityDataHolder.getInstance().getCarbonRealmService().setClaimManager(claimManager);
        }

        log.info("Realm service registered successfully.");
        log.info("Carbon-Security bundle activated successfully.");
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
            name = "IdentityStoreConnectorFactory",
            service = IdentityStoreConnectorFactory.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterIdentityStoreConnectorFactory"
    )
    protected void registerIdentityStoreConnectorFactory(IdentityStoreConnectorFactory identityStoreConnectorFactory,
                                                         Map<String, String> properties) {

        String connectorId = properties.get("connector-type");
        CarbonSecurityDataHolder.getInstance()
                .registerIdentityStoreConnectorFactory(connectorId, identityStoreConnectorFactory);
    }

    protected void unregisterIdentityStoreConnectorFactory(
            IdentityStoreConnectorFactory identityStoreConnectorFactory) {
    }

    @Reference(
            name = "CredentialStoreConnectorFactory",
            service = CredentialStoreConnectorFactory.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterCredentialStoreConnectorFactory"
    )
    protected void registerCredentialStoreConnectorFactory(
            CredentialStoreConnectorFactory credentialStoreConnectorFactory, Map<String, String> properties) {

        String connectorId = properties.get("connector-type");
        CarbonSecurityDataHolder.getInstance()
                .registerCredentialStoreConnectorFactory(connectorId, credentialStoreConnectorFactory);
    }

    protected void unregisterCredentialStoreConnectorFactory(
            CredentialStoreConnectorFactory credentialStoreConnectorFactory) {
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
            name = "ClaimManager",
            service = ClaimManager.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterClaimManager"
    )
    protected void registerClaimManager(ClaimManager claimManager, Map<String, String> properties) {

        String claimMangerName = properties.get("claim-manager");
        if (claimMangerName != null && !claimMangerName.trim().isEmpty() && CarbonSecurityDataHolder.getInstance()
                .getClaimConfig() != null && claimMangerName.equals(CarbonSecurityDataHolder.getInstance()
                .getClaimConfig().getClaimManager())) {

            try {
                claimManager.init(CarbonSecurityDataHolder.getInstance().getClaimConfig().getClaimMappings());
                CarbonSecurityDataHolder.getInstance().getCarbonRealmService().setClaimManager(claimManager);
            } catch (ClaimManagerException e) {
                log.error("Failed to initialize Claim Manager - " + claimMangerName, e);
            }
        }
    }

    protected void unregisterClaimManager(ClaimManager claimManager) {

        CarbonSecurityDataHolder.getInstance().getCarbonRealmService().setClaimManager(null);
    }

    /**
     * Initialize authentication related configs.
     *
     * @param bundleContext
     */
    private void initAuthenticationConfigs(BundleContext bundleContext) {

        // Initialize proxy login module
        ProxyLoginModule.init(bundleContext);

        CarbonSecurityDataHolder.getInstance().setBundleContext(bundleContext);

        // Set CarbonJAASConfiguration as the implantation of Configuration
        CarbonJAASConfiguration configuration = new CarbonJAASConfiguration();
        configuration.init();

        //Registering login module provided by the bundle
        Hashtable<String, String> usernamePasswordLoginModuleProps = new Hashtable<>();
        usernamePasswordLoginModuleProps.put(ProxyLoginModule.LOGIN_MODULE_SEARCH_KEY,
                UsernamePasswordLoginModule.class.getName());
        bundleContext.registerService(LoginModule.class, new UserNamePasswordLoginModuleFactory(),
                usernamePasswordLoginModuleProps);

        // Registering callback handler factories
        Hashtable<String, String> usernamePasswordCallbackHandlerProps = new Hashtable<>();
        usernamePasswordCallbackHandlerProps.put(CarbonCallbackHandler.SUPPORTED_LOGIN_MODULE,
                CarbonSecurityConstants.USERNAME_PASSWORD_LOGIN_MODULE);
        bundleContext.registerService(CarbonCallbackHandler.class, new UsernamePasswordCallbackHandlerFactory(),
                usernamePasswordCallbackHandlerProps);
    }

    /**
     * Initialize authorization related configs.
     *
     * @param bundleContext
     */
    private void initAuthorizationConfigs(BundleContext bundleContext) {

        // Set default permissions for all bundles
        setDefaultPermissions(bundleContext);

        // Registering CarbonPolicy
        CarbonPolicy policy = new CarbonPolicy();
        Policy.setPolicy(policy);
    }

    /**
     * Set default permissions for all bundles using PermissionAdmin.
     *
     * @param context
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

        permissionAdmin.setDefaultPermissions(permissionInfoList.toArray(new PermissionInfo[permissionInfoList.size()
                ]));
    }

    /**
     * Get PermissionAdmin.
     *
     * @param context
     * @return
     */
    private PermissionAdmin getPermissionAdmin(BundleContext context) {
        return (PermissionAdmin) context.getService(context.getServiceReference(PermissionAdmin.class.getName()));
    }
}

