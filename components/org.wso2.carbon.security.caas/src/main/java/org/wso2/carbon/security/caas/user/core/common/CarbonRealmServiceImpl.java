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

package org.wso2.carbon.security.caas.user.core.common;

import org.wso2.carbon.security.caas.user.core.claim.ClaimManager;
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.domain.InMemoryDomainManager;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.DomainManagerException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.CacheBackedAuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.CacheBackedIdentityStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;
import org.wso2.carbon.security.caas.user.core.store.IdentityStoreImpl;

/**
 * Basic user realm service.
 *
 * @param <T1>
 * @param <T2>
 */
public class CarbonRealmServiceImpl<T1 extends IdentityStore, T2 extends CredentialStore>
        implements RealmService<T1, T2> {

    private ClaimManager claimManager;

    /**
     * Authorization store in the realm service.
     */
    private AuthorizationStore authorizationStore;

    /**
     * Credential store instance in the realm service.
     */
    private T2 credentialStore;

    /**
     * Credential store instance in the realm service.
     */
    private T1 identityStore;

    public CarbonRealmServiceImpl(StoreConfig storeConfig) throws IdentityStoreException, AuthorizationStoreException,
            CredentialStoreException, DomainManagerException {

        if (storeConfig.isCacheEnabled()) {
            this.authorizationStore = new CacheBackedAuthorizationStore(storeConfig
                    .getAuthorizationStoreCacheConfigMap());
            this.identityStore = (T1) new CacheBackedIdentityStore(storeConfig
                    .getIdentityStoreCacheConfigMap());
        } else {
            this.identityStore = (T1) new IdentityStoreImpl();
            this.authorizationStore = new AuthorizationStoreImpl();
        }

        this.credentialStore = (T2) new CredentialStoreImpl();

        DomainManager domainManager = new InMemoryDomainManager();

        credentialStore.init(domainManager, storeConfig.getCredentialConnectorConfigMap());
        identityStore.init(domainManager, storeConfig.getIdentityConnectorConfigMap());
        authorizationStore.init(storeConfig.getAuthorizationConnectorConfigMap());
    }

    @Override
    public AuthorizationStore getAuthorizationStore() {
        return authorizationStore;
    }

    @Override
    public ClaimManager getClaimManager() {
        return claimManager;
    }

    @Override
    public T1 getIdentityStore() {
        return this.identityStore;
    }

    @Override
    public T2 getCredentialStore() {
        return this.credentialStore;
    }

    /**
     * Set the claim manger.
     *
     * @param claimManager Claim manager.
     */
    public void setClaimManager(ClaimManager claimManager) {
        this.claimManager = claimManager;
    }
}
