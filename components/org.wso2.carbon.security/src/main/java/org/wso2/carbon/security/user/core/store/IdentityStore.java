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
import org.wso2.carbon.security.user.core.bean.Group;
import org.wso2.carbon.security.user.core.bean.User;
import org.wso2.carbon.security.user.core.config.IdentityStoreConfig;
import org.wso2.carbon.security.user.core.constant.UserStoreConstants;
import org.wso2.carbon.security.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.user.core.exception.StoreException;
import org.wso2.carbon.security.user.core.service.RealmService;
import org.wso2.carbon.security.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.user.core.store.connector.IdentityStoreConnectorFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Represents a virtual identity store to abstract the underlying stores.
 * @since 1.0.0
 */
public class IdentityStore {

    private static final Logger log = LoggerFactory.getLogger(IdentityStore.class);

    private RealmService realmService;
    private Map<String, IdentityStoreConnector> identityStoreConnectors = new HashMap<>();

    /**
     * Initialize this instance.
     * @throws IdentityStoreException
     */
    public void init(RealmService realmService, Map<String, IdentityStoreConfig> identityStoreConfigs) 
            throws IdentityStoreException {

        this.realmService = realmService;

        if (identityStoreConfigs.isEmpty()) {
            throw new StoreException("At least one identity store configuration must present.");
        }

        for (Map.Entry<String, IdentityStoreConfig> identityStoreConfig : identityStoreConfigs.entrySet()) {

            String connectorType = (String) identityStoreConfig.getValue().getStoreProperties()
                    .get(UserStoreConstants.CONNECTOR_TYPE);
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

    /**
     * Get the user from username.
     * @param username Username of the user.
     * @return User.
     * @throws IdentityStoreException
     */
    public User getUser(String username) throws IdentityStoreException {

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            User.UserBuilder userBuilder = identityStoreConnector.getUser(username);

            if (userBuilder != null) {
                return userBuilder
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build();
            }
        }

        throw new IdentityStoreException("No user found for the given name.");
    }


    /**
     * Get the user from user Id.
     * @param userId Id of the user.
     * @return User.
     * @throws IdentityStoreException
     */
    public User getUserfromId(String userId) throws IdentityStoreException {

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            User.UserBuilder userBuilder = identityStoreConnector.getUserFromId(userId);

            if (userBuilder != null) {
                return userBuilder
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build();
            }
        }

        throw new IdentityStoreException("No user found for the given user id.");
    }

    /**
     * List all users in User Store according to the filter pattern.
     * @param filterPattern Filter patter to filter users.
     * @param offset Offset for list of users.
     * @param length Length from the offset.
     * @return List of users match the filter pattern.
     * @throws IdentityStoreException
     */
    public List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException {

        List<User> users = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            users.addAll(identityStoreConnector.listUsers(filterPattern, offset, length)
                    .stream()
                    .map(userBuilder -> userBuilder
                            .setIdentityStore(realmService.getIdentityStore())
                            .setAuthorizationStore(realmService.getAuthorizationStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        return users;
    }

    /**
     * Get user attribute values.
     * @param userID Id of the user.
     * @param userStoreId Id of the user store which this user belongs.
     * @return Map of user attributes.
     * @throws IdentityStoreException
     */
    public Map<String, String> getUserAttributeValues(String userID, String userStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(userStoreId);
        return identityStoreConnector.getUserAttributeValues(userID);
    }

    /**
     * Get user's claim values for the given URIs.
     * @param userID Id of the user.
     * @param attributeNames Attribute names.
     * @param userStoreId Id of the user store which this user belongs.
     * @return Map of user attributes.
     * @throws IdentityStoreException
     */
    public Map<String, String> getUserAttributeValues(String userID, List<String> attributeNames, String userStoreId)
            throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(userStoreId);
        return identityStoreConnector.getUserAttributeValues(userID, attributeNames);
    }

    /**
     * Get the group from name.
     * @param groupName Name of the group.
     * @return Group
     */
    public Group getGroup(String groupName) throws IdentityStoreException {

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            Group.GroupBuilder groupBuilder = identityStoreConnector.getGroup(groupName);

            if (groupBuilder != null) {
                return groupBuilder
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build();
            }
        }

        throw new IdentityStoreException("No group found for the given name.");
    }

    /**
     * Get the group from group id.
     * @param groupId Group id.
     * @return Group.
     */
    public Group getGroupFromId(String groupId) throws IdentityStoreException {

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            Group.GroupBuilder groupBuilder = identityStoreConnector.getGroupById(groupId);

            if (groupBuilder != null) {
                return groupBuilder
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build();
            }
        }

        throw new IdentityStoreException("No group found for the given group id.");
    }

    /**
     * List groups according to the filter pattern.
     * @param filterPattern Filter pattern for to list groups.
     * @param offset Offset for the group list.
     * @param length Length from the offset.
     * @return List of groups that matches the filter pattern.
     * @throws IdentityStoreException
     */
    public List<Group> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException {

        List<Group> groups = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectors.values()) {
            groups.addAll(identityStoreConnector.listGroups(filterPattern, offset, length)
                    .stream()
                    .map(groupBuilder -> groupBuilder
                            .setIdentityStore(realmService.getIdentityStore())
                            .setAuthorizationStore(realmService.getAuthorizationStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        return groups;
    }

    /**
     * Get the groups assigned to the specified user.
     * @param userId Id of the user.
     * @param userStoreId Id of the user store which this user belongs.
     * @return List of Group assigned to the user.
     * @throws IdentityStoreException
     */
    public List<Group> getGroupsOfUser(String userId, String userStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(userStoreId);
        return identityStoreConnector.getGroupsOfUser(userId)
                .stream()
                .map(groupBuilder -> groupBuilder
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .setIdentityStore(realmService.getIdentityStore())
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Get the users assigned to the specified group.
     * @param groupID Id of the group.
     * @param userStoreId User store id of this group.
     * @return List of users assigned to the group.
     * @throws IdentityStoreException
     */
    public List<User> getUsersOfGroup(String groupID, String userStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(userStoreId);
        return identityStoreConnector.getUsersOfGroup(groupID)
                .stream()
                .map(userBuilder -> userBuilder
                        .setIdentityStore(realmService.getIdentityStore())
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Checks whether the user is in the group.
     * @param userId Id of the user.
     * @param groupId Id of the group.
     * @param userStoreId Id of the user store which this user belongs.
     * @return True if the user is in the group.
     */
    public boolean isUserInGroup(String userId, String groupId, String userStoreId) throws IdentityStoreException {

        IdentityStoreConnector identityStoreConnector = identityStoreConnectors.get(userStoreId);
        return identityStoreConnector.isUserInGroup(userId, groupId);
    }
}
