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

package org.wso2.carbon.security.caas.internal.config;

import java.util.Collections;
import java.util.List;

/**
 * StoreConfigs Bean
 *
 * @since 1.0.0
 */
public class StoreConfigFile {

    private boolean enableCache;

    private StoreConfigEntry credentialStore;

    private StoreConfigEntry identityStore;

    private StoreConfigEntry authorizationStore;

    private List<StoreConnectorConfigEntry> storeConnectors;

    public boolean isEnableCache() {
        return enableCache;
    }

    public void setEnableCache(boolean enableCache) {
        this.enableCache = enableCache;
    }

    public StoreConfigEntry getCredentialStore() {
        return credentialStore;
    }

    public void setCredentialStore(StoreConfigEntry credentialStore) {
        this.credentialStore = credentialStore;
    }

    public StoreConfigEntry getIdentityStore() {
        return identityStore;
    }

    public void setIdentityStore(StoreConfigEntry identityStore) {
        this.identityStore = identityStore;
    }

    public StoreConfigEntry getAuthorizationStore() {
        return authorizationStore;
    }

    public void setAuthorizationStore(StoreConfigEntry authorizationStore) {
        this.authorizationStore = authorizationStore;
    }

    public List<StoreConnectorConfigEntry> getStoreConnectors() {
        if (storeConnectors == null) {
            return Collections.EMPTY_LIST;
        }
        return storeConnectors;
    }

    public void setStoreConnectors(List<StoreConnectorConfigEntry> storeConnectors) {
        this.storeConnectors = storeConnectors;
    }

}

