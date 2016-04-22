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

package org.wso2.carbon.security.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.security.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.user.core.config.IdentityStoreConfig;
import org.wso2.carbon.security.user.core.store.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.user.core.store.connector.IdentityStoreConnector;

import java.util.HashMap;
import java.util.Map;

/**
 * Carbon security data holder.
 * @since 1.0.0
 */
public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();
    private CarbonRealmServiceImpl carbonRealmService;
    private Map<String, AuthorizationStoreConnector> authorizationStoreConnectorMap = new HashMap<>();
    private Map<String, CredentialStoreConnector> credentialStoreConnectorMap = new HashMap<>();
    private Map<String, IdentityStoreConnector> identityStoreConnectorMap = new HashMap<>();
    private Map<String, CredentialStoreConfig> credentialStoreConfigMap = new HashMap<>();
    private Map<String, IdentityStoreConfig> identityStoreConfigMap = new HashMap<>();
    private Map<String, AuthorizationStoreConfig> authorizationStoreConfigMap = new HashMap<>();
    private BundleContext bundleContext = null;

    private CarbonSecurityDataHolder() {

    }

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

    public void registerAuthorizationStoreConnector(String key, AuthorizationStoreConnector
            authorizationStoreConnector) {
        authorizationStoreConnectorMap.put(key, authorizationStoreConnector);
    }

    public void registerCredentialStoreConnector(String key, CredentialStoreConnector credentialStoreConnector) {
        credentialStoreConnectorMap.put(key, credentialStoreConnector);
    }

    public void registerIdentityStoreConnector(String key, IdentityStoreConnector identityStoreConnector) {
        identityStoreConnectorMap.put(key, identityStoreConnector);
    }

    public Map<String, AuthorizationStoreConnector> getAuthorizationStoreConnectorMap() {
        return authorizationStoreConnectorMap;
    }

    public Map<String, CredentialStoreConnector> getCredentialStoreConnectorMap() {
        return credentialStoreConnectorMap;
    }

    public Map<String, IdentityStoreConnector> getIdentityStoreConnectorMap() {
        return identityStoreConnectorMap;
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
        return bundleContext;
    }
}
