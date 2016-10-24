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
import org.wso2.carbon.security.caas.api.CarbonCallback;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Domain;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.constant.UserCoreConstants;
import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.DomainException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

/**
 * Represents a virtual credential store to abstract the underlying stores.
 *
 * @since 1.0.0
 */
public class CredentialStoreImpl implements CredentialStore {

    private static final Logger log = LoggerFactory.getLogger(CredentialStoreImpl.class);

    private DomainManager domainManager;


    @Override
    public void init(
            DomainManager domainManager,
            Map<String, CredentialStoreConnectorConfig> credentialConnectorConfigs)
            throws CredentialStoreException {

        this.domainManager = domainManager;

        if (credentialConnectorConfigs.isEmpty()) {
            throw new StoreException("At least one credential store configuration must present.");
        }

        for (Map.Entry<String, CredentialStoreConnectorConfig> credentialStoreConfig :
                credentialConnectorConfigs.entrySet()) {

            String connectorType = credentialStoreConfig.getValue().getConnectorType();
            CredentialStoreConnectorFactory credentialStoreConnectorFactory = CarbonSecurityDataHolder.getInstance()
                    .getCredentialStoreConnectorFactoryMap().get(connectorType);

            if (credentialStoreConnectorFactory == null) {
                throw new StoreException("No credential store connector factory found for given type.");
            }

            CredentialStoreConnector credentialStoreConnector = credentialStoreConnectorFactory.getInstance();
            credentialStoreConnector.init(credentialStoreConfig.getValue());
        }

        if (log.isDebugEnabled()) {
            log.debug("Credential store successfully initialized.");
        }
    }

    @Override
    public AuthenticationContext authenticate(Callback[] callbacks)
            throws AuthenticationFailure {

        // As user related data is in the Identity store and the credential data is in the Credential store,
        // we need to get the user unique id from Identity store to get the user related credential information
        // from the Credential store.

        // TODO: Override the NameCallBack class in a way so that you can obtain the unique attribute name.
        NameCallback callback = (NameCallback) Arrays.stream(callbacks)
                .filter(c ->
                        c instanceof NameCallback)
                .collect(Collectors.toList())
                .get(0);

        if (callback == null) {
            throw new AuthenticationFailure("NameCallBack not found in callback list");
        }

        String username = callback.getName();

        String[] domainSplit = username.split(CarbonSecurityConstants.URL_SPLITTER);

        // Remove domain information before forwarding the callback to the credential store
        if (domainSplit.length > 1) {
            String domainUnawareUsername = domainSplit[1];

            callback.setName(domainUnawareUsername);
        }

        User user;
        try {
            // Get the user using given callbacks. We need to find the user unique id.
            user = CarbonSecurityDataHolder.getInstance()
                    .getCarbonRealmService().getIdentityStore().getUser(username);

            // Crete a new call back array from existing one and add new user data (user id and identity store id)
            // as a carbon callback to the new array.
            Callback[] newCallbacks = new Callback[callbacks.length + 1];
            System.arraycopy(callbacks, 0, newCallbacks, 0, callbacks.length);

            // User data will be a map.
            CarbonCallback<Map> carbonCallback = new CarbonCallback<>(null);
            Map<String, String> userData = new HashMap<>();
            userData.put(UserCoreConstants.USER_ID, user.getUserId());
            carbonCallback.setContent(userData);

            // New callback always will be the last element.
            newCallbacks[newCallbacks.length - 1] = carbonCallback;

            // Old callbacks with the new carbon callback.
            callbacks = newCallbacks;
        } catch (IdentityStoreException | UserNotFoundException e) {
            throw new AuthenticationFailure("Error occurred while retrieving user.", e);
        }

        // TODO: Resolve domain
        Map<String, CredentialStoreConnector> credentialStoreConnectorsMap;

        try {
            credentialStoreConnectorsMap = resolveDomain(username).getCredentialStoreConnectorMap();
        } catch (CredentialStoreException e) {
            credentialStoreConnectorsMap = Collections.emptyMap();
            log.error("Error occurred in obtaining the credential store connector map", e);
        }

        for (CredentialStoreConnector credentialStoreConnector : credentialStoreConnectorsMap.values()) {

            // We need to check whether this credential store can handle this kind of callbacks.
            if (!credentialStoreConnector.canHandle(callbacks)) {
                continue;
            }

            try {
                // If the authentication failed, there will be an authentication failure exception.
                credentialStoreConnector.authenticate(callbacks);

                return new AuthenticationContext(user);
            } catch (CredentialStoreException e) {

                if (log.isDebugEnabled()) {
                    log.debug(String
                            .format("Failed to authenticate user using credential store connector %s",
                                    credentialStoreConnector.getCredentialStoreId()), e);
                }
            }
        }

        throw new AuthenticationFailure("Invalid user credentials.");
    }

    /**
     * Resolve domain using username.
     *
     * @param username String username
     * @return Domain for the username
     * @throws CredentialStoreException CredentialStoreException on unable to locate username
     */
    private Domain resolveDomain(String username) throws CredentialStoreException {

        try {
            return domainManager.getDomainFromUserName(username);
        } catch (DomainException e) {
            throw new CredentialStoreException(String
                    .format("Domain for username %s do not exist", username), e);
        }
    }

}
