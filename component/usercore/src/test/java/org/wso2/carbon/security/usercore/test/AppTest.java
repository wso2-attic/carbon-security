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

import org.junit.Assert;
import org.junit.Test;
import org.wso2.carbon.security.usercore.bean.Permission;
import org.wso2.carbon.security.user.core.bean.User;
import org.wso2.carbon.security.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.usercore.exception.AuthorizationFailure;
import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.store.AuthorizationStore;
import org.wso2.carbon.security.user.core.store.CredentialStore;
import org.wso2.carbon.security.user.core.store.IdentityStore;
import org.wso2.carbon.security.usercore.bean.Permission;
import org.wso2.carbon.security.usercore.exception.AuthorizationFailure;
import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.store.AuthorizationStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Main test class.
 */
public class AppTest {

    private CredentialStore authManager = null;
    private AuthorizationStore authzManager = null;
    private IdentityStore identityStore = null;

    public void configure() throws IdentityStoreException {

        authManager = CarbonRealmServiceImpl.getInstance().getCredentialStore();
        authzManager = CarbonRealmServiceImpl.getInstance().getAuthorizationStore();
        identityStore = CarbonRealmServiceImpl.getInstance().getIdentityStore();
    }

    private void addUser() throws IdentityStoreException, AuthorizationStoreException {

        Map<String, String> userClaims = new HashMap<>();
        userClaims.put("userName", "admin");

        User user = identityStore
                .addUser(userClaims, "password".toCharArray(), new ArrayList<String>());
        String userId = user.getUserID();

        authzManager.updateRolesInUser(userId, "internal/everyone", "PRIMARY");
        authzManager.addRolePermission("internal/everyone", "/permissions/login", "PRIMARY");
    }

    @Test
    public void testApp() throws IdentityStoreException, AuthorizationStoreException, AuthorizationFailure,
            AuthenticationFailure {

        configure();
        addUser();

        String userName = "admin";
        String password = "password";

        AuthenticationContext context = authManager.authenticate("userName", userName, password.toCharArray());
        String userId = context.getUser().getUserID();
        Assert.assertTrue(authzManager.isUserAuthorized(userId, new Permission("/permissions/login")));
    }
}
