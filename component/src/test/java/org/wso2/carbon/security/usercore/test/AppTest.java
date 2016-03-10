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

package org.wso2.carbon.security.usercore.test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.usercore.exception.AuthenticationFailure;
import org.wso2.carbon.security.usercore.exception.AuthorizationFailure;
import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;
import org.wso2.carbon.security.usercore.exception.CredentialStoreException;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.store.AuthorizationStore;
import org.wso2.carbon.security.usercore.store.CredentialStore;
import org.wso2.carbon.security.usercore.store.IdentityStore;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

/**
 * Main test class.
 */
public class AppTest {

    Logger log = LoggerFactory.getLogger(AppTest.class);

    private CredentialStore authManager = null;
    private AuthorizationStore authzManager = null;
    private IdentityStore identityStore = null;

    public void configure() {

        try {
            authManager = CarbonRealmServiceImpl.getInstance().getCredentialStore();
            authzManager = CarbonRealmServiceImpl.getInstance().getAuthorizationStore();
            identityStore = CarbonRealmServiceImpl.getInstance().getIdentityStore();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Test
    public void testApp() throws IdentityStoreException, AuthorizationStoreException, AuthorizationFailure,
            AuthenticationFailure, CredentialStoreException {

        Callback [] callbacks = new Callback[2];
        Callback passwordCallback = new PasswordCallback("password", false);
        Callback nameCallback = new NameCallback("username");

        callbacks[0] = passwordCallback;
        callbacks[1] = nameCallback;

        // authManager.authenticate(callbacks);
    }
}
