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

package org.wso2.carbon.security.usercore.store;

import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.internal.config.StoreConfigBuilder;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.usercore.config.CredentialStoreConfig;
import org.wso2.carbon.security.usercore.connector.CredentialStoreConnector;
import org.wso2.carbon.security.usercore.constant.UserStoreConstants;
import org.wso2.carbon.security.usercore.context.AuthenticationContext;
import org.wso2.carbon.security.usercore.exception.AuthenticationFailure;
import org.wso2.carbon.security.usercore.exception.CredentialStoreException;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.service.RealmService;

import java.io.IOException;
import javax.security.auth.callback.Callback;

/**
 * This class represents a data store which contains user credentials.
 */
public class CredentialStore {

    private RealmService realmService;
    private CredentialStoreConnector credentialStoreConnector;

    public void init(RealmService realmService) throws IOException, CredentialStoreException {

        this.realmService = realmService;

        CredentialStoreConfig credentialStoreConfig = StoreConfigBuilder
                .buildCredentialStoreConfig(UserStoreConstants.USER_STORE_CONFIGURATION_FILE);

        // TODO: Get the store connector id from configuration file.
        credentialStoreConnector = CarbonSecurityDataHolder.getInstance().getCredentialStoreConnectorMap()
                .get("JDBCCredentialStore");
        credentialStoreConnector.init(credentialStoreConfig);
    }

    /**
     * Authenticate the user.
     * @param callbacks Callbacks to get the user details.
     * @return @see{AuthenticationContext} if the authentication is success. @see{AuthenticationFailure} otherwise.
     * @throws AuthenticationFailure
     * @throws IdentityStoreException
     */
    public AuthenticationContext authenticate(Callback[] callbacks) throws AuthenticationFailure,
            CredentialStoreException, IdentityStoreException {

        User user = credentialStoreConnector.authenticate(callbacks);
        if (user != null) {
            return new AuthenticationContext(user);
        }
        throw new AuthenticationFailure("Invalid user credentials.");
    }
}
