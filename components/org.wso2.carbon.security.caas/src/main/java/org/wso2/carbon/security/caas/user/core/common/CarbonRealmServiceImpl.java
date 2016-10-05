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
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.CacheBackedAuthorizationStore;

/**
 * Basic user realm service.
 */
public class CarbonRealmServiceImpl implements RealmService {

    private AuthorizationStore authorizationStore = new AuthorizationStoreImpl();
    private DomainManager domainManager = new InMemoryDomainManager();
    private ClaimManager claimManager;

    public CarbonRealmServiceImpl(StoreConfig storeConfig) throws IdentityStoreException, AuthorizationStoreException,
            CredentialStoreException {

        if (storeConfig.isCacheEnabled()) {
            this.authorizationStore = new CacheBackedAuthorizationStore(storeConfig
                    .getAuthorizationStoreCacheConfigMap());
        }

        authorizationStore.init(storeConfig.getAuthorizationConnectorConfigMap());
    }

    @Override
    public AuthorizationStore getAuthorizationStore() {
        return authorizationStore;
    }

    @Override
    public DomainManager getDomainManager() {
        return domainManager;
    }

    @Override
    public ClaimManager getClaimManager() {
        return claimManager;
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
