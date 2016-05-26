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
import org.wso2.carbon.security.caas.internal.config.ClaimConfig;
import org.wso2.carbon.security.caas.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConfig;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Carbon security data holder.
 * @since 1.0.0
 */
public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();
    private CarbonRealmServiceImpl carbonRealmService;
    private Map<String, AuthorizationStoreConnectorFactory> authorizationStoreConnectorFactoryMap = new HashMap<>();
    private Map<String, CredentialStoreConnectorFactory> credentialStoreConnectorFactoryMap = new HashMap<>();
    private Map<String, IdentityStoreConnectorFactory> identityStoreConnectorFactoryMap = new HashMap<>();
    private Map<String, CredentialStoreConfig> credentialStoreConfigMap = new HashMap<>();
    private Map<String, IdentityStoreConfig> identityStoreConfigMap = new HashMap<>();
    private Map<String, AuthorizationStoreConfig> authorizationStoreConfigMap = new HashMap<>();
    private ClaimConfig claimConfig;
    private BundleContext bundleContext = null;

    private CarbonSecurityDataHolder() {
    }

    /**
     * Get the instance of this class.
     * @return CarbonSecurityDataHolder.
     */
    public static CarbonSecurityDataHolder getInstance() {
        return instance;
    }

    public void registerCarbonRealmService(CarbonRealmServiceImpl carbonRealmService) {
        this.carbonRealmService = carbonRealmService;
    }

    public CarbonRealmServiceImpl getCarbonRealmService() {

        if (this.carbonRealmService == null) {
            throw new IllegalStateException("Carbon Realm Service is null.");
        }
        return this.carbonRealmService;
    }

    /**
     * Register authorization store connector factory.
     * @param key Id of the factory.
     * @param authorizationStoreConnectorFactory AuthorizationStoreConnectorFactory.
     */
    public void registerAuthorizationStoreConnectorFactory(String key, AuthorizationStoreConnectorFactory
            authorizationStoreConnectorFactory) {
        authorizationStoreConnectorFactoryMap.put(key, authorizationStoreConnectorFactory);
    }

    /**
     * Register credential store connector factory.
     * @param key Id of the factory.
     * @param credentialStoreConnectorFactory CredentialStoreConnectorFactory.
     */
    public void registerCredentialStoreConnectorFactory(String key,
                                                 CredentialStoreConnectorFactory credentialStoreConnectorFactory) {
        credentialStoreConnectorFactoryMap.put(key, credentialStoreConnectorFactory);
    }

    /**
     * Register identity store connector factory.
     * @param key Id of the factory.
     * @param identityStoreConnectorFactory IdentityStoreConnectorFactory.
     */
    public void registerIdentityStoreConnectorFactory(String key,
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

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    public Map<String, CredentialStoreConfig> getCredentialStoreConfigMap() {
        return credentialStoreConfigMap;
    }

    public void addCredentialStoreConfig(String connectorName, CredentialStoreConfig storeConfig) {
        this.credentialStoreConfigMap.put(connectorName, storeConfig);
    }

    public Map<String, IdentityStoreConfig> getIdentityStoreConfigMap() {
        return identityStoreConfigMap;
    }

    public void addIdentityStoreConfig(String connectorName, IdentityStoreConfig storeConfig) {
        this.identityStoreConfigMap.put(connectorName, storeConfig);
    }

    public Map<String, AuthorizationStoreConfig> getAuthorizationStoreConfigMap() {
        return authorizationStoreConfigMap;
    }

    public void addAuthorizationStoreConfig(String connectorName, AuthorizationStoreConfig storeConfig) {
        this.authorizationStoreConfigMap.put(connectorName, storeConfig);
    }

    public BundleContext getBundleContext() {
        if (this.bundleContext == null) {
            throw new IllegalStateException("BundleContext is null.");
        }
        return bundleContext;
    }

    public ClaimConfig getClaimConfig() {
        return claimConfig;
    }

    public void setClaimConfig(ClaimConfig claimConfig) {
        this.claimConfig = claimConfig;
    }
}
