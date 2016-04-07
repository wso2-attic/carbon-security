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

package org.wso2.carbon.security.usercore.common;

import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;
import org.wso2.carbon.security.usercore.exception.CredentialStoreException;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.service.RealmService;
import org.wso2.carbon.security.usercore.store.AuthorizationStore;
import org.wso2.carbon.security.usercore.store.CredentialStore;
import org.wso2.carbon.security.usercore.store.IdentityStore;

import java.io.IOException;

/**
 * Basic user realm service.
 */
public class CarbonRealmServiceImpl implements RealmService {

    private CredentialStore credentialStore = new CredentialStore();
    private AuthorizationStore authorizationStore = new AuthorizationStore();
    private IdentityStore identityStore = new IdentityStore();

    public CarbonRealmServiceImpl() throws IOException, IdentityStoreException, CredentialStoreException,
            AuthorizationStoreException {
        
        super();
        credentialStore.init(this);
        authorizationStore.init(this);
        identityStore.init(this);
    }

    /**
     * Get the credential store.
     * @return @see CredentialStore
     */
    @Override
    public CredentialStore getCredentialStore() {
        return credentialStore;
    }

    /**
     * Get the authorization store.
     * @return @see AuthorizationStore.
     */
    @Override
    public AuthorizationStore getAuthorizationStore() {
        return authorizationStore;
    }

    /**
     * Get the identity store.
     * @return @see IdentityStore
     */
    @Override
    public IdentityStore getIdentityStore() {
        return identityStore;
    }

}
