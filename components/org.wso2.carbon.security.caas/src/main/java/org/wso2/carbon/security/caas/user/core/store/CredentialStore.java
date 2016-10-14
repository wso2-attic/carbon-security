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

package org.wso2.carbon.security.caas.user.core.store;

import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;

import javax.security.auth.callback.Callback;
import java.util.Map;

/**
 * Represents a virtual credential store to abstract the underlying stores.
 *
 * @since 1.0.0
 */
public interface CredentialStore {

    /**
     * Initialize credential store.
     *
     * @param domainManager              DomainManager instance for which is shared by the identity store
     *                                   and the credentials store.
     * @param credentialConnectorConfigs Connector configs related to the credential store.
     * @throws CredentialStoreException Credential Store Exception.
     */
    void init(DomainManager domainManager, Map<String, CredentialStoreConnectorConfig> credentialConnectorConfigs)
            throws CredentialStoreException;

    /**
     * Authenticate the user.
     *
     * @param callbacks Callbacks to get the user details.
     * @return If the authentication is success. AuthenticationFailure otherwise.
     * @throws AuthenticationFailure Authentication Failure.
     */
    AuthenticationContext authenticate(Callback[] callbacks) throws AuthenticationFailure;
}
