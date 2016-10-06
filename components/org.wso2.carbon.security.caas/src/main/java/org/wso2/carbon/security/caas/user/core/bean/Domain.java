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

package org.wso2.carbon.security.caas.user.core.bean;

import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.store.CacheBackedIdentityStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;
import org.wso2.carbon.security.caas.user.core.store.IdentityStoreImpl;

/**
 * Represents a domain.
 */
public class Domain {

    /**
     * Name of the domain.
     */
    private String domainName;

    /**
     * Credential store instance for the domain.
     */
    private CredentialStore credentialStore;

    /**
     * Identity store instance for the domain.
     */
    private IdentityStore identityStore;

    public Domain(String domainName, StoreConfig storeConfig)
            throws CredentialStoreException, IdentityStoreException {

        this.domainName = domainName;

        if (storeConfig.isCacheEnabled()) {
            this.identityStore = new CacheBackedIdentityStore(storeConfig.getIdentityStoreCacheConfigMap());
        } else {
            this.identityStore = new IdentityStoreImpl();
        }

        this.credentialStore = new CredentialStoreImpl();

        credentialStore.init(this, storeConfig.getCredentialConnectorConfigMap());
        identityStore.init(this, storeConfig.getIdentityConnectorConfigMap());
    }

    /**
     * Get the domain name.
     *
     * @return String - domain name
     */
    public String getDomainName() {
        return domainName;
    }

    /**
     * Get the identity store.
     *
     * @return IdentityStore identity store.
     */
    public IdentityStore getIdentityStore() {
        return identityStore;
    }

    /**
     * Get the credential store.
     *
     * @return CredentialStore credential store.
     */
    public CredentialStore getCredentialStore() {
        return credentialStore;
    }
}
