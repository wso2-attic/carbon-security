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

package org.wso2.carbon.security.user.core.store.connector;

import org.wso2.carbon.security.user.core.bean.User;
import org.wso2.carbon.security.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.user.core.exception.CredentialStoreException;

import javax.security.auth.callback.Callback;

/**
 * Credential store connector.
 */
public interface CredentialStoreConnector {

    /**
     * Initialize the Credential store connector.
     * @param credentialStoreConfig Credential store configurations.
     * @throws CredentialStoreException
     */
    void init(CredentialStoreConfig credentialStoreConfig) throws CredentialStoreException;

    /**
     * Get the ID of this credential store.
     * @return ID as a String.
     */
    String getCredentialStoreId();

    /**
     * Authenticate user using callbacks.
     * @param callbacks Callbacks to get the user attributes.
     * @return Authentication result, User if success, null otherwise.
     * @throws CredentialStoreException
     */
    User authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure;

    /**
     *
     * @param callbacks
     * @return
     */
    boolean canHandle(Callback[] callbacks);
}
