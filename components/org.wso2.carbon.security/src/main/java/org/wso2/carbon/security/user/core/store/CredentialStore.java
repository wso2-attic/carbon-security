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

package org.wso2.carbon.security.user.core.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.user.core.service.RealmService;
import org.wso2.carbon.security.user.core.store.connector.CredentialStoreConnector;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;

/**
 * This class represents a data store which contains user credentials.
 * @since 1.0.0
 */
public class CredentialStore {

    private Map<String, CredentialStoreConnector> credentialStoreConnectors = new HashMap<>();
    private static final Logger log = LoggerFactory.getLogger(CredentialStore.class);

    public void init(RealmService realmService) throws IOException, CredentialStoreException {

        Map<String, CredentialStoreConfig> credentialStoreConfigs = CarbonSecurityDataHolder.getInstance()
                .getCredentialStoreConfigMap();

        for (Map.Entry<String, CredentialStoreConfig> credentialStoreConfig : credentialStoreConfigs.entrySet()) {

            CredentialStoreConnector credentialStoreConnector = CarbonSecurityDataHolder.getInstance()
                    .getCredentialStoreConnectorMap().get(credentialStoreConfig.getKey());
            credentialStoreConnector.init(credentialStoreConfig.getValue());
            credentialStoreConnectors.put(credentialStoreConfig.getKey(), credentialStoreConnector);
        }

        if (log.isDebugEnabled()) {
            log.debug("Credential store successfully initialized.");
        }
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

        AuthenticationFailure authenticationFailure = new AuthenticationFailure("Invalid user credentials.");

        for (CredentialStoreConnector credentialStoreConnector : credentialStoreConnectors.values()) {

            try {
                return new AuthenticationContext(credentialStoreConnector.authenticate(callbacks));
            } catch (AuthenticationFailure failure) {
                authenticationFailure.addSuppressed(failure);
            }
        }
        throw authenticationFailure;
    }
}
