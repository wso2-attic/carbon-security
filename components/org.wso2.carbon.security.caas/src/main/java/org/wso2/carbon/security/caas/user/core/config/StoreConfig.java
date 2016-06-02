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

package org.wso2.carbon.security.caas.user.core.config;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a complete configurations of the stores.
 */
public class StoreConfig {

    private boolean enableCache;
    private boolean enableCacheForAuthorizationStore;
    private boolean enableCacheForIdentityStore;
    private boolean enableCacheForCredentialStore;
    private Map<String, AuthorizationConnectorConfig> authorizationStoreConfigMap = new HashMap<>();
    private Map<String, IdentityConnectorConfig> identityStoreConfigMap = new HashMap<>();
    private Map<String, CredentialConnectorConfig> credentialStoreConfigMap = new HashMap<>();

    public boolean isEnableCache() {
        return enableCache;
    }

    public void setEnableCache(boolean enableCache) {
        this.enableCache = enableCache;
    }

    public boolean isEnableCacheForAuthorizationStore() {
        return enableCacheForAuthorizationStore;
    }

    public void setEnableCacheForAuthorizationStore(boolean enableCacheForAuthorizationStore) {
        this.enableCacheForAuthorizationStore = enableCacheForAuthorizationStore;
    }

    public boolean isEnableCacheForIdentityStore() {
        return enableCacheForIdentityStore;
    }

    public void setEnableCacheForIdentityStore(boolean enableCacheForIdentityStore) {
        this.enableCacheForIdentityStore = enableCacheForIdentityStore;
    }

    public boolean isEnableCacheForCredentialStore() {
        return enableCacheForCredentialStore;
    }

    public void setEnableCacheForCredentialStore(boolean enableCacheForCredentialStore) {
        this.enableCacheForCredentialStore = enableCacheForCredentialStore;
    }

    public Map<String, AuthorizationConnectorConfig> getAuthorizationConnectorConfigMap() {
        return authorizationStoreConfigMap;
    }

    public void setAuthorizationStoreConfigMap(Map<String, AuthorizationConnectorConfig> authorizationStoreConfigMap) {
        this.authorizationStoreConfigMap = authorizationStoreConfigMap;
    }

    public void addAuthorizationStoreConfig(String name, AuthorizationConnectorConfig authorizationConnectorConfig) {
        this.authorizationStoreConfigMap.put(name, authorizationConnectorConfig);
    }

    public Map<String, IdentityConnectorConfig> getIdentityConnectorConfigMap() {
        return identityStoreConfigMap;
    }

    public void setIdentityStoreConfigMap(Map<String, IdentityConnectorConfig> identityStoreConfigMap) {
        this.identityStoreConfigMap = identityStoreConfigMap;
    }

    public void addIdentityStoreConfig(String name, IdentityConnectorConfig identityConnectorConfig) {
        this.identityStoreConfigMap.put(name, identityConnectorConfig);
    }

    public Map<String, CredentialConnectorConfig> getCredentialConnectorConfigMap() {
        return credentialStoreConfigMap;
    }

    public void setCredentialStoreConfigMap(Map<String, CredentialConnectorConfig> credentialStoreConfigMap) {
        this.credentialStoreConfigMap = credentialStoreConfigMap;
    }

    public void addCredentialStoreConfig(String name, CredentialConnectorConfig credentialConnectorConfig) {
        this.credentialStoreConfigMap.put(name, credentialConnectorConfig);
    }
}
