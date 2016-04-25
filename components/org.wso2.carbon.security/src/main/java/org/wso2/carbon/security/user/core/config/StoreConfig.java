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

package org.wso2.carbon.security.user.core.config;

/**
 * Represents a complete configurations of the stores.
 */
public class StoreConfig {

    private AuthorizationStoreConfig authorizationStoreConfig;
    private IdentityStoreConfig identityStoreConfig;
    private CredentialStoreConfig credentialStoreConfig;

    public AuthorizationStoreConfig getAuthorizationStoreConfig() {
        return authorizationStoreConfig;
    }

    public void setAuthorizationStoreConfig(AuthorizationStoreConfig authorizationStoreConfig) {
        this.authorizationStoreConfig = authorizationStoreConfig;
    }

    public IdentityStoreConfig getIdentityStoreConfig() {
        return identityStoreConfig;
    }

    public void setIdentityStoreConfig(IdentityStoreConfig identityStoreConfig) {
        this.identityStoreConfig = identityStoreConfig;
    }

    public CredentialStoreConfig getCredentialStoreConfig() {
        return credentialStoreConfig;
    }

    public void setCredentialStoreConfig(CredentialStoreConfig credentialStoreConfig) {
        this.credentialStoreConfig = credentialStoreConfig;
    }
}
