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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;

import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;

/**
 * Represents a virtual credential store to abstract the underlying stores.
 * @since 1.0.0
 */
public class CredentialStoreImpl implements CredentialStore {

    private static final Logger log = LoggerFactory.getLogger(CredentialStoreImpl.class);

    private RealmService realmService;
    private Map<String, CredentialStoreConnector> credentialStoreConnectors = new HashMap<>();

    @Override
    public void init(RealmService realmService, Map<String, CredentialStoreConfig> credentialStoreConfigs)
            throws CredentialStoreException {

        this.realmService = realmService;

        if (credentialStoreConfigs.isEmpty()) {
            throw new StoreException("At least one credential store configuration must present.");
        }

        for (Map.Entry<String, CredentialStoreConfig> credentialStoreConfig : credentialStoreConfigs.entrySet()) {

            String connectorType = credentialStoreConfig.getValue().getConnectorType();
            CredentialStoreConnectorFactory credentialStoreConnectorFactory = CarbonSecurityDataHolder.getInstance()
                    .getCredentialStoreConnectorFactoryMap().get(connectorType);

            if (credentialStoreConnectorFactory == null) {
                throw new StoreException("No credential store connector factory found for given type.");
            }

            CredentialStoreConnector credentialStoreConnector = credentialStoreConnectorFactory.getInstance();
            credentialStoreConnector.init(credentialStoreConfig.getKey(), credentialStoreConfig.getValue());

            credentialStoreConnectors.put(credentialStoreConfig.getKey(), credentialStoreConnector);
        }

        if (log.isDebugEnabled()) {
            log.debug("Credential store successfully initialized.");
        }
    }

    @Override
    public AuthenticationContext authenticate(Callback[] callbacks) throws AuthenticationFailure {

        AuthenticationFailure authenticationFailure = new AuthenticationFailure("Invalid user credentials.");

        for (CredentialStoreConnector credentialStoreConnector : credentialStoreConnectors.values()) {

            try {
                User.UserBuilder userBuilder = credentialStoreConnector.authenticate(callbacks);
                if (userBuilder == null) {
                    throw new AuthenticationFailure("User builder is null.");
                }
                return new AuthenticationContext(userBuilder
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build());
            } catch (AuthenticationFailure | CredentialStoreException failure) {
                authenticationFailure.addSuppressed(failure);
            }
        }
        throw authenticationFailure;
    }
}
