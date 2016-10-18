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
import org.wso2.carbon.caching.CarbonCachingService;
import org.wso2.carbon.security.caas.internal.config.domain.DomainConfig;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimStore;
import org.wso2.carbon.security.caas.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.caas.user.core.exception.CarbonSecurityDataHolderException;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.user.UserManager;

import java.util.HashMap;
import java.util.Map;

/**
 * Carbon security data holder.
 *
 * @since 1.0.0
 */
public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();
    private CarbonRealmServiceImpl carbonRealmService;
    private Map<String, AuthorizationStoreConnectorFactory> authorizationStoreConnectorFactoryMap = new HashMap<>();
    private Map<String, CredentialStoreConnectorFactory> credentialStoreConnectorFactoryMap = new HashMap<>();
    private Map<String, IdentityStoreConnectorFactory> identityStoreConnectorFactoryMap = new HashMap<>();
    private CarbonCachingService carbonCachingService;
    private DomainConfig domainConfig;
    private BundleContext bundleContext = null;

    private MetaClaimStore metaClaimStore;

    private UserManager userManager;

    private CarbonSecurityDataHolder() {
    }

    /**
     * Get the instance of this class.
     *
     * @return CarbonSecurityDataHolder.
     */
    public static CarbonSecurityDataHolder getInstance() {
        return instance;
    }

    void registerCarbonRealmService(CarbonRealmServiceImpl carbonRealmService) {
        this.carbonRealmService = carbonRealmService;
    }

    public CarbonRealmServiceImpl getCarbonRealmService() {

        if (carbonRealmService == null) {
            throw new IllegalStateException("Carbon Realm Service is null.");
        }
        return carbonRealmService;
    }

    /**
     * Register authorization store connector factory.
     *
     * @param key                                Id of the factory.
     * @param authorizationStoreConnectorFactory AuthorizationStoreConnectorFactory.
     */
    void registerAuthorizationStoreConnectorFactory(String key, AuthorizationStoreConnectorFactory
            authorizationStoreConnectorFactory) {
        authorizationStoreConnectorFactoryMap.put(key, authorizationStoreConnectorFactory);
    }

    /**
     * Register credential store connector factory.
     *
     * @param key                             Id of the factory.
     * @param credentialStoreConnectorFactory CredentialStoreConnectorFactory.
     */
    void registerCredentialStoreConnectorFactory(String key,
                                                 CredentialStoreConnectorFactory credentialStoreConnectorFactory) {
        credentialStoreConnectorFactoryMap.put(key, credentialStoreConnectorFactory);
    }

    /**
     * Register identity store connector factory.
     *
     * @param key                           Id of the factory.
     * @param identityStoreConnectorFactory IdentityStoreConnectorFactory.
     */
    void registerIdentityStoreConnectorFactory(String key,
                                               IdentityStoreConnectorFactory identityStoreConnectorFactory) {
        identityStoreConnectorFactoryMap.put(key, identityStoreConnectorFactory);
    }

    public Map<String, AuthorizationStoreConnectorFactory> getAuthorizationStoreConnectorFactoryMap() {
        return authorizationStoreConnectorFactoryMap;
    }

    public Map<String, CredentialStoreConnectorFactory> getCredentialStoreConnectorFactoryMap() {
        return credentialStoreConnectorFactoryMap;
    }

    public Map<String, IdentityStoreConnectorFactory> getIdentityStoreConnectorFactoryMap() {
        return identityStoreConnectorFactoryMap;
    }

    void registerCacheService(CarbonCachingService carbonCachingService) {
        this.carbonCachingService = carbonCachingService;
    }

    public CarbonCachingService getCarbonCachingService() throws CarbonSecurityDataHolderException {

        if (carbonCachingService == null) {
            throw new CarbonSecurityDataHolderException("Carbon caching service is null");
        }

        return carbonCachingService;
    }

    void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    public BundleContext getBundleContext() {

        if (bundleContext == null) {
            throw new IllegalStateException("BundleContext is null.");
        }
        return bundleContext;
    }

    public DomainConfig getDomainConfig() throws CarbonSecurityDataHolderException {

        if (domainConfig == null) {
            throw new CarbonSecurityDataHolderException("Domain configuration is null.");
        }

        return domainConfig;
    }

    public void setDomainConfig(DomainConfig domainConfig) {
        this.domainConfig = domainConfig;
    }

    public MetaClaimStore getMetaClaimStore() {
        return metaClaimStore;
    }

    public void setMetaClaimStore(MetaClaimStore metaClaimStore) {
        this.metaClaimStore = metaClaimStore;
    }

    public UserManager getUserManager() {
        return userManager;
    }

    public void setUserManager(UserManager userManager) {
        this.userManager = userManager;
    }
}
