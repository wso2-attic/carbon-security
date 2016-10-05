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

package org.wso2.carbon.security.caas.user.core.store.connector;

import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;

import javax.security.auth.callback.Callback;

/**
 * Credential store connector.
 */
public interface CredentialStoreConnector {

    /**
     * Initialize the Credential store connector.
     * @param credentialStoreConnectorConfig Credential store configurations for this connector.
     * @param storeId Id of this store.
     * @throws CredentialStoreException Credential Store Exception.
     */
    void init(String storeId, CredentialStoreConnectorConfig credentialStoreConnectorConfig)
            throws CredentialStoreException;

    /**
     * Get the ID of this credential store.
     * @return ID of the credential store.
     */
    String getCredentialStoreId();

    /**
     * Authenticate user using callbacks. Throws {@link AuthenticationFailure} if authentication is not successful.
     *
     * @param callbacks Callbacks to get the user attributes.
     * @throws CredentialStoreException Credential Store Exception.
     * @throws AuthenticationFailure Authentication failure.
     */
    void authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure;

    /**
     * Checks whether this connector can handle the given callbacks.
     * @param callbacks Array of callbacks.
     * @return True if there are all of the callbacks required for this connector.
     */
    boolean canHandle(Callback[] callbacks);

    /**
     * Get the Credential store config.
     * @return CredentialStoreConnectorConfig.
     */
    CredentialStoreConnectorConfig getCredentialStoreConfig();
}
