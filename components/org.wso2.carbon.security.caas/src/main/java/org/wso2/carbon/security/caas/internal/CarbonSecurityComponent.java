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
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;
import org.wso2.carbon.security.caas.api.CarbonCallbackHandler;
import org.wso2.carbon.security.caas.api.CarbonJAASConfiguration;
import org.wso2.carbon.security.caas.api.CarbonPolicy;
import org.wso2.carbon.security.caas.api.module.UsernamePasswordLoginModule;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.boot.ProxyLoginModule;
import org.wso2.carbon.security.caas.internal.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.internal.config.PermissionConfigBuilder;
import org.wso2.carbon.security.caas.internal.config.PermissionConfigFile;
import org.wso2.carbon.security.caas.internal.config.StoreConfigBuilder;
import org.wso2.carbon.security.caas.internal.config.domain.DomainConfig;
import org.wso2.carbon.security.caas.internal.config.domain.DomainConfigBuilder;
import org.wso2.carbon.security.caas.internal.config.domain.DomainIdentityStoreConnectorConfigEntry;
import org.wso2.carbon.security.caas.internal.osgi.UserNamePasswordLoginModuleFactory;
import org.wso2.carbon.security.caas.internal.osgi.UsernamePasswordCallbackHandlerFactory;
import org.wso2.carbon.security.caas.user.core.bean.Domain;
import org.wso2.carbon.security.caas.user.core.claim.ClaimManager;
import org.wso2.carbon.security.caas.user.core.claim.FileBasedMetaClaimStore;
import org.wso2.carbon.security.caas.user.core.claim.InMemoryClaimManager;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaim;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimMapping;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimStore;
import org.wso2.carbon.security.caas.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.DomainConfigException;
import org.wso2.carbon.security.caas.user.core.exception.DomainException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.MetaClaimStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionConfigException;
import org.wso2.carbon.security.caas.user.core.exception.UserManagerException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.CacheBackedAuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.CacheBackedIdentityStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;
import org.wso2.carbon.security.caas.user.core.store.IdentityStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.user.FileBasedUserManager;
import org.wso2.carbon.security.caas.user.core.user.UserManager;

import java.io.IOException;
import java.security.Policy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.security.auth.spi.LoginModule;

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
            log.error("Error occurred in un getting service", e);
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
        CarbonSecurityDataHolder.getInstance().getCarbonRealmService().setClaimManager(claimManager);
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

        // Initialize proxy login module.
        ProxyLoginModule.init(bundleContext);

        // Set CarbonJAASConfiguration as the implementation of Configuration.
        CarbonJAASConfiguration configuration = new CarbonJAASConfiguration();
        configuration.init();

        // Registering login module provided by the bundle.
        Hashtable<String, String> usernamePasswordLoginModuleProps = new Hashtable<>();
        usernamePasswordLoginModuleProps.put(ProxyLoginModule.LOGIN_MODULE_SEARCH_KEY,
                UsernamePasswordLoginModule.class.getName());
        bundleContext.registerService(LoginModule.class, new UserNamePasswordLoginModuleFactory(),
                usernamePasswordLoginModuleProps);

        // Registering callback handler factories.
        Hashtable<String, String> usernamePasswordCallbackHandlerProps = new Hashtable<>();
        usernamePasswordCallbackHandlerProps.put(CarbonCallbackHandler.SUPPORTED_LOGIN_MODULE,
                CarbonSecurityConstants.USERNAME_PASSWORD_LOGIN_MODULE);
        bundleContext.registerService(CarbonCallbackHandler.class, new UsernamePasswordCallbackHandlerFactory(),
                usernamePasswordCallbackHandlerProps);
    }

    /**
     * Initialize authorization related configs.
     *
     * @param bundleContext BundleContext
     */
    private void initAuthorizationConfigs(BundleContext bundleContext)
            throws PermissionConfigException {

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
    private void setDefaultPermissions(BundleContext context) throws PermissionConfigException {

        PermissionAdmin permissionAdmin = getPermissionAdmin(context);

        if (permissionAdmin == null) {
            return;
        }

        PermissionConfigFile permissionConfigFile = PermissionConfigBuilder.buildPermissionConfig();

        if (permissionConfigFile != null) {

            if (permissionConfigFile.getPermissions().isEmpty()) {
                log.error("Permission entry list cannot be empty");
            }

            List<PermissionInfo> permissionInfoList = permissionConfigFile.getPermissions()
                    .stream()
                    .map(permissionEntry ->
                            new PermissionInfo(permissionEntry.getType(),
                                    permissionEntry.getName(),
                                    permissionEntry.getActions()))
                    .collect(Collectors.toList());

            permissionAdmin.setDefaultPermissions(
                    permissionInfoList.toArray(new PermissionInfo[permissionInfoList.size()]));
        }
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

        CarbonSecurityDataHolder carbonSecurityDataHolder = CarbonSecurityDataHolder.getInstance();
        BundleContext bundleContext = carbonSecurityDataHolder.getBundleContext();

        // If security manager is enabled init authorization configs
        if (System.getProperty("java.security.manager") != null) {

            try {
                initAuthorizationConfigs(bundleContext);
            } catch (PermissionConfigException e) {
                log.error("Error in setting up default permissions", e);
            }
        }

        StoreConfig storeConfig = StoreConfigBuilder.getStoreConfig();


        try {

            MetaClaimStore metaClaimStore = new FileBasedMetaClaimStore(
                    CarbonSecurityConstants.getCarbonHomeDirectory().toString() + "conf/security/" +
                            CarbonSecurityConstants.CLAIM_STORE_FILE);

            carbonSecurityDataHolder.setMetaClaimStore(metaClaimStore);

            UserManager userManager = new FileBasedUserManager();

            carbonSecurityDataHolder.setUserManager(userManager);

            DomainConfig domainConfig = DomainConfigBuilder.getDomainConfig();
            carbonSecurityDataHolder.setDomainConfig(domainConfig);

            DomainManager domainManager = createDomainManagerFromConfig(domainConfig, storeConfig);

            AuthorizationStore authorizationStore;
            CredentialStore credentialStore;
            IdentityStore identityStore;

            if (storeConfig.isCacheEnabled()) {
                authorizationStore = new CacheBackedAuthorizationStore(storeConfig
                        .getAuthorizationStoreCacheConfigMap());
                identityStore = new CacheBackedIdentityStore(storeConfig
                        .getIdentityStoreCacheConfigMap());
            } else {
                identityStore = new IdentityStoreImpl();
                authorizationStore = new AuthorizationStoreImpl();
            }

            credentialStore = new CredentialStoreImpl();

            credentialStore.init(domainManager, storeConfig.getCredentialConnectorConfigMap());
            identityStore.init(domainManager, storeConfig.getIdentityConnectorConfigMap());
            authorizationStore.init(storeConfig.getAuthorizationConnectorConfigMap());


            // Register the carbon realm service.
            CarbonRealmServiceImpl<IdentityStore, CredentialStore> carbonRealmService
                    = new CarbonRealmServiceImpl(identityStore, credentialStore, authorizationStore);

            carbonSecurityDataHolder.registerCarbonRealmService(carbonRealmService);
            realmServiceRegistration = bundleContext.registerService(RealmService.class.getName(), carbonRealmService,
                    null);
            log.info("Realm service registered successfully.");

            // Initialize and register the claim manager.
            InMemoryClaimManager claimManager = new InMemoryClaimManager();

            carbonSecurityDataHolder.getCarbonRealmService().setClaimManager(claimManager);
        } catch (CredentialStoreException | AuthorizationStoreException | IdentityStoreException e) {
            log.error("Error occurred in initialising store", e);
        } catch (DomainException e) {
            log.error("Error occurred in creating the domain manager from the domain config", e);
        } catch (DomainConfigException | MetaClaimStoreException e) {
            log.error("Error occurred in building the domain configuration", e);
        } catch (IOException e) {
            log.error("Error initializing claim store from file", e);
        } catch (UserManagerException e) {
            log.error("Error initializing FileBasedUserManager", e);
        }

        log.info("Carbon-Security bundle activated successfully.");
    }

    /**
     * Create the domains and domain manager from the domain configuration.
     *
     * @param domainConfig Domain configuration
     * @return DomainManager
     * @throws DomainException Domain Manager Exception
     */
    private DomainManager createDomainManagerFromConfig(DomainConfig domainConfig, StoreConfig storeConfig) throws
            DomainException, DomainConfigException, MetaClaimStoreException {

        DomainManager domainManager = new DomainManager();
        MetaClaimStore metaClaimStore = CarbonSecurityDataHolder.getInstance().getMetaClaimStore();

        Map<String, Integer> domainNameToDomainPriorityMap = domainConfig.getDomainNameToDomainPriorityMap();

        Map<String, IdentityStoreConnectorConfig> identityStoreConnectorConfigs =
                storeConfig.getIdentityConnectorConfigMap();

        Map<String, IdentityStoreConnectorFactory> identityStoreConnectorFactories =
                CarbonSecurityDataHolder.getInstance().getIdentityStoreConnectorFactoryMap();

        Map<String, Domain> domains = new HashMap<>();

        for (Map.Entry<String, List<DomainIdentityStoreConnectorConfigEntry>> domainConfigEntry :
                domainConfig.getDomainIdentityStoreConnectors().entrySet()) {

            String domainName = domainConfigEntry.getKey();
            int domainPriority = domainNameToDomainPriorityMap.get(domainName);

            // Create new domain
            Domain domain = new Domain(domainName, domainPriority);
            domainManager.addDomain(domain);
            domains.put(domainName, domain);

            // Domain connector meta claims mappings
            Map<String, List<MetaClaimMapping>> connectorMetaClaimMappings = new HashMap<>();

            for (DomainIdentityStoreConnectorConfigEntry domainIdentityStoreConnectorConfigEntry :
                    domainConfigEntry.getValue()) {
                String identityStoreConnectorId = domainIdentityStoreConnectorConfigEntry.getIdentityStoreConnectorId();
                IdentityStoreConnectorConfig identityStoreConnectorConfig =
                        identityStoreConnectorConfigs.get(identityStoreConnectorId);

                IdentityStoreConnector identityStoreConnector = identityStoreConnectorFactories
                        .get(identityStoreConnectorConfig.getConnectorType()).getConnector();

                domain.addIdentityStoreConnectorPrimaryAttribute(identityStoreConnectorId,
                        identityStoreConnectorConfig.getPrimaryAttributeName());

                List<String> uniqueAttributes = identityStoreConnectorConfig.getUniqueAttributes();
                List<String> otherAttributes = identityStoreConnectorConfig.getOtherAttributes();

                domain.addIdentityStoreConnector(identityStoreConnector);

                List<MetaClaimMapping> metaClaimMappings = new ArrayList<>();

                for (Map.Entry<String, String> attributeMapping :
                        domainIdentityStoreConnectorConfigEntry.getAttributeMappings().entrySet()) {

                    String attributeName = attributeMapping.getValue();
                    boolean unique = false;

                    if (uniqueAttributes.contains(attributeName)) {
                        unique = true;
                    } else if (!otherAttributes.contains(attributeName)) {
                        throw new DomainConfigException("Attribute " + attributeName
                                + " not found in connector for claim mapping");
                    }

                    MetaClaim metaClaim = metaClaimStore.getMetaClaim(attributeMapping.getKey());
                    metaClaimMappings.add(new MetaClaimMapping(metaClaim, identityStoreConnectorId, attributeName,
                            unique));
                }

                connectorMetaClaimMappings.put(identityStoreConnectorId, metaClaimMappings);

            }


            domain.setClaimMappings(connectorMetaClaimMappings);

        }

        for (Map.Entry<String, CredentialStoreConnectorConfig> credentialStoreConnectorConfigEntry :
                storeConfig.getCredentialConnectorConfigMap().entrySet()) {

            String credentialStoreConnectorId = credentialStoreConnectorConfigEntry.getKey();

            CredentialStoreConnectorConfig credentialStoreConnectorConfig =
                    credentialStoreConnectorConfigEntry.getValue();

            CredentialStoreConnector credentialStoreConnector = CarbonSecurityDataHolder.getInstance()
                    .getCredentialStoreConnectorFactoryMap()
                    .get(credentialStoreConnectorConfig.getConnectorType()).getInstance();

            try {
                credentialStoreConnector.init(credentialStoreConnectorId, credentialStoreConnectorConfig);

                String domainName = credentialStoreConnectorConfig.getDomainName();
                Domain domain = domains.get(domainName);

                if (domain != null) {
                    domain.addCredentialStoreConnector(credentialStoreConnector);
                    domain.addCredentialStoreConnectorPrimaryAttribute(credentialStoreConnectorId,
                            credentialStoreConnectorConfig.getPrimaryAttributeName());
                } else {
                    log.error("Domain " + domainName + " was not found when creating CredentialStoreConnector "
                            + credentialStoreConnectorId);
                }
            } catch (CredentialStoreException e) {
                log.error("Error initializing CredentialStoreConnector " + credentialStoreConnectorId);
            }
        }

        return domainManager;
    }
}

