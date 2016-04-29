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

    private Map<String, AuthorizationStoreConfig> authorizationStoreConfigMap = new HashMap<>();
    private Map<String, IdentityStoreConfig> identityStoreConfigMap = new HashMap<>();
    private Map<String, CredentialStoreConfig> credentialStoreConfigMap = new HashMap<>();

    public Map<String, AuthorizationStoreConfig> getAuthorizationStoreConfigMap() {
        return authorizationStoreConfigMap;
    }

    public void setAuthorizationStoreConfigMap(Map<String, AuthorizationStoreConfig> authorizationStoreConfigMap) {
        this.authorizationStoreConfigMap = authorizationStoreConfigMap;
    }

    public void addAuthorizationStoreConfig(String name, AuthorizationStoreConfig authorizationStoreConfig) {
        this.authorizationStoreConfigMap.put(name, authorizationStoreConfig);
    }

    public Map<String, IdentityStoreConfig> getIdentityStoreConfigMap() {
        return identityStoreConfigMap;
    }

    public void setIdentityStoreConfigMap(Map<String, IdentityStoreConfig> identityStoreConfigMap) {
        this.identityStoreConfigMap = identityStoreConfigMap;
    }

    public void addIdentityStoreConfig(String name, IdentityStoreConfig identityStoreConfig) {
        this.identityStoreConfigMap.put(name, identityStoreConfig);
    }

    public Map<String, CredentialStoreConfig> getCredentialStoreConfigMap() {
        return credentialStoreConfigMap;
    }

    public void setCredentialStoreConfigMap(Map<String, CredentialStoreConfig> credentialStoreConfigMap) {
        this.credentialStoreConfigMap = credentialStoreConfigMap;
    }

    public void addCredentialStoreConfig(String name, CredentialStoreConfig credentialStoreConfig) {
        this.credentialStoreConfigMap.put(name, credentialStoreConfig);
    }
}
