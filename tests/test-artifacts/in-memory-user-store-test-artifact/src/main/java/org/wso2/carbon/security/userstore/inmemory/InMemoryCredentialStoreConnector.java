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

package org.wso2.carbon.security.userstore.inmemory;

import org.wso2.carbon.security.user.core.bean.User;
import org.wso2.carbon.security.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.userstore.inmemory.util.InMemoryStoreUtil;

import java.util.Arrays;
import java.util.UUID;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

/**
 * InMemory connector for the credential store.
 *
 * @since 1.0.0
 */
public class InMemoryCredentialStoreConnector implements CredentialStoreConnector {


    @Override
    public void init(CredentialStoreConfig credentialStoreConfig) throws CredentialStoreException {

    }

    @Override
    public String getCredentialStoreId() {
        return null;
    }

    @Override
    public User.UserBuilder authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {

        if (callbacks == null || callbacks.length < 2) {
            throw new AuthenticationFailure("Invalid credentials");
        }

        String username = null;
        char[] password = null;
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getName();
            } else if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
            throw new AuthenticationFailure("Invalid credentials");
        }

        char[] storedPassword = InMemoryStoreUtil.getPassword(username);
        if (storedPassword != null && Arrays.equals(storedPassword, password)) {
            return new User.UserBuilder(username, UUID.randomUUID().toString(), "PRIMARY", -1);
        } else {
            throw new AuthenticationFailure("Invalid credentials");
        }
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {
        return false;
    }
}
