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
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityConnectorConfig;
import org.wso2.carbon.security.caas.user.core.constant.UserCoreConstants;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.security.auth.callback.Callback;

/**
 * Represents a virtual identity store to abstract the underlying stores.
 * @since 1.0.0
 */
public class IdentityStoreImpl implements IdentityStore {

    private static final Logger log = LoggerFactory.getLogger(IdentityStoreImpl.class);

    private RealmService realmService;
    private Map<String, IdentityConnectorConfig> identityConnectorConfigs;
    private Map<String, IdentityStoreConnector> identityStoreConnectors = new HashMap<>();

    @Override
    public void init(RealmService realmService, Map<String, IdentityConnectorConfig> identityConnectorConfigs)
            throws IdentityStoreException {

        this.realmService = realmService;
        this.identityConnectorConfigs = identityConnectorConfigs;

        if (identityConnectorConfigs.isEmpty()) {
            throw new StoreException("At least one identity store configuration must present.");
        }

        for (Map.Entry<String, IdentityConnectorConfig> identityStoreConfig : identityConnectorConfigs.entrySet()) {

            String connectorType = identityStoreConfig.getValue().getConnectorType();
            IdentityStoreConnectorFactory identityStoreConnectorFactory = CarbonSecurityDataHolder.getInstance()
                    .getIdentityStoreConnectorFactoryMap().get(connectorType);

            if (identityStoreConnectorFactory == null) {
                throw new StoreException("No identity store connector factory found for given type.");
            }

            IdentityStoreConnector identityStoreConnector = identityStoreConnectorFactory.getInstance();
            identityStoreConnector.init(identityStoreConfig.getKey(), identityStoreConfig.getValue());

            identityStoreConnectors.put(identityStoreConfig.getKey(), identityStoreConnector);
        }

        if (log.isDebugEnabled()) {
            log.debug("Identity store successfully initialized.");
        }
    }

    @Override
    public User getUser(String username) throws IdentityStoreException, UserNotFoundException {

        UserNotFoundException userNotFoundException = new UserNotFoundException("User not found for the given name.");

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            try {
                return identityStoreConnector.getUser(username)
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .setClaimManager(realmService.getClaimManager())
                        .build();
            } catch (UserNotFoundException e) {
                userNotFoundException.addSuppressed(e);
            }
        }
        throw userNotFoundException;
    }

    @Override
    public User getUser(Callback [] callbacks) throws IdentityStoreException, UserNotFoundException {

        UserNotFoundException userNotFoundException = new
                UserNotFoundException("User not found for the given callbacks.");

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            try {
                return identityStoreConnector.getUser(callbacks)
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .setClaimManager(realmService.getClaimManager())
                        .build();
            } catch (UserNotFoundException e) {
                userNotFoundException.addSuppressed(e);
            }
        }
        throw userNotFoundException;
    }

    @Override
    public User getUserFromId(String userId, String identityStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(identityStoreId);
        User.UserBuilder userBuilder = identityStoreConnector.getUserFromId(userId);

        if (userBuilder == null) {
            throw new IdentityStoreException("No user found for the given user id in the given identity store.");
        }

        return userBuilder
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .setClaimManager(realmService.getClaimManager())
                .build();
    }

    @Override
    public List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException {

        List<User> users = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {

            // Get the total count of users in the identity store.
            int userCount;
            try {
                userCount = identityStoreConnector.getUserCount();
            } catch (UnsupportedOperationException e) {
                log.warn("Count operation is not supported by this identity store. Running the operation in " +
                        "performance intensive mode.");
                userCount = identityStoreConnector.listUsers("*", 0, -1).size();
            }

            // If there are users in this identity store more than the offset, we can get users from this offset.
            // If this offset exceeds the available count of the current identity store, move to the next
            // identity store.
            if (userCount > offset) {
                users.addAll(identityStoreConnector.listUsers(filterPattern, offset, length)
                        .stream()
                        .map(userBuilder -> userBuilder
                                .setIdentityStore(realmService.getIdentityStore())
                                .setAuthorizationStore(realmService.getAuthorizationStore())
                                .setClaimManager(realmService.getClaimManager())
                                .build())
                        .collect(Collectors.toList()));
                length -= users.size();
                offset = 0;
            } else {
                offset -= userCount;
            }

            // If we retrieved all the required users.
            if (length == 0) {
                break;
            }
        }

        return users;
    }

    @Override
    public Map<String, String> getUserAttributeValues(String userID, String userStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(userStoreId);
        return identityStoreConnector.getUserAttributeValues(userID);
    }

    @Override
    public Map<String, String> getUserAttributeValues(String userID, List<String> attributeNames, String userStoreId)
            throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(userStoreId);
        return identityStoreConnector.getUserAttributeValues(userID, attributeNames);
    }

    @Override
    public Group getGroup(String groupName) throws IdentityStoreException, GroupNotFoundException {

        GroupNotFoundException groupNotFoundException =
                new GroupNotFoundException("Group not found for the given name");

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            try {
                return identityStoreConnector.getGroup(groupName)
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build();
            } catch (GroupNotFoundException e) {
                groupNotFoundException.addSuppressed(e);
            }
        }
        throw groupNotFoundException;
    }

    @Override
    public Group getGroupFromId(String groupId, String identityStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(identityStoreId);
        Group.GroupBuilder groupBuilder = identityStoreConnector.getGroupById(groupId);

        if (groupBuilder == null) {
            throw new IdentityStoreException("No group found for the given group id in the given identity store.");
        }

        return groupBuilder
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build();
    }

    @Override
    public List<Group> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException {

        List<Group> groups = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {

            // Get the total count of groups in the identity store.
            int groupCount;
            try {
                groupCount = identityStoreConnector.getGroupCount();
            } catch (UnsupportedOperationException e) {
                log.warn("Count operation is not supported by this identity store. Running the operation in " +
                        "performance intensive mode.");
                groupCount = identityStoreConnector.listUsers("*", 0, -1).size();
            }

            // If there are groups in this identity store more than the offset, we can get groups from this offset.
            // If this offset exceeds the available count of the current identity store, move to the next
            // identity store.
            if (groupCount > offset) {
                groups.addAll(identityStoreConnector.listGroups(filterPattern, offset, length)
                        .stream()
                        .map(groupBuilder -> groupBuilder
                                .setIdentityStore(realmService.getIdentityStore())
                                .setAuthorizationStore(realmService.getAuthorizationStore())
                                .build())
                        .collect(Collectors.toList()));
                length -= groups.size();
                offset = 0;
            } else {
                offset -= groupCount;
            }

            // If we retrieved all the required users.
            if (length == 0) {
                break;
            }
        }

        return groups;
    }

    @Override
    public Map<String, String> getGroupAttributeValues(String groupId, String identityStoreId)
            throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(identityStoreId);
        return identityStoreConnector.getGroupAttributeValues(groupId);
    }

    @Override
    public Map<String, String> getGroupAttributeValues(String groupId, String identityStoreId,
                                                       List<String> attributeNames)
            throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(identityStoreId);
        return identityStoreConnector.getGroupAttributeValues(groupId, attributeNames);
    }

    @Override
    public List<Group> getGroupsOfUser(String userId, String identityStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(identityStoreId);
        return identityStoreConnector.getGroupsOfUser(userId)
                .stream()
                .map(groupBuilder -> groupBuilder
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .setIdentityStore(realmService.getIdentityStore())
                        .build())
                .collect(Collectors.toList());
    }

    @Override
    public List<User> getUsersOfGroup(String groupID, String identityStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(identityStoreId);
        return identityStoreConnector.getUsersOfGroup(groupID)
                .stream()
                .map(userBuilder -> userBuilder
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .setClaimManager(realmService.getClaimManager())
                        .build())
                .collect(Collectors.toList());
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId, String identityStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(identityStoreId);
        return identityStoreConnector.isUserInGroup(userId, groupId);
    }

    @Override
    public Map<String, String> getAllIdentityStoreNames() {
        return identityConnectorConfigs.entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey,
                        entry -> entry.getValue().getStoreProperties()
                                .getProperty(UserCoreConstants.USERSTORE_DISPLAY_NAME, "")));
    }
}
