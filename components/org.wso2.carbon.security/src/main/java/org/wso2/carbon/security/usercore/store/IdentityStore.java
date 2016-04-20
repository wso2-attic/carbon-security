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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.usercore.config.IdentityStoreConfig;
import org.wso2.carbon.security.usercore.connector.IdentityStoreConnector;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.service.RealmService;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Represents a virtual identity store to abstract the underlying user connector.
 */
public class IdentityStore {

    private RealmService realmService;
    private static final Logger log = LoggerFactory.getLogger(IdentityStore.class);
    private IdentityStoreConnector identityStoreConnector;

    /**
     * Initialize this instance.
     * @throws IOException
     * @throws IdentityStoreException
     */
    public void init(RealmService realmService) throws IOException, IdentityStoreException {

        this.realmService = realmService;

        // TODO: Handle multiple user stores.

        Map.Entry<String, IdentityStoreConfig> firstEntry = CarbonSecurityDataHolder.getInstance()
                .getIdentityStoreConfigMap().entrySet().iterator().next();

        String identityStoreId = firstEntry.getKey();
        IdentityStoreConfig identityStoreConfig = firstEntry.getValue();

        identityStoreConnector = CarbonSecurityDataHolder.getInstance().getIdentityStoreConnectorMap()
                .get(identityStoreId);
        identityStoreConnector.init(identityStoreConfig);
    }

    /**
     * Checks whether the user is in the group.
     * @param userId Id of the user.
     * @param groupId Id of the group.
     * @return True if the user is in the group.
     */
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException {
        return identityStoreConnector.isUserInGroup(userId, groupId);
    }

    /**
     * Get the groups assigned to the specified user.
     * @param userID Id of the user.
     * @return List of Group assigned to the user.
     * @throws IdentityStoreException
     */
    public List<Group> getGroupsOfUser(String userID) throws IdentityStoreException {
        return identityStoreConnector.getGroupsOfUser(userID);
    }

    /**
     * Get the users assigned to the specified group.
     * @param groupID Id of the group.
     * @param userStoreId User store id of this group.
     * @return List of users assigned to the group.
     * @throws IdentityStoreException
     */
    public List<User> getUsersOfGroup(String groupID, String userStoreId) throws IdentityStoreException {
        // TODO: Why do we need user store id here?
        return identityStoreConnector.getUsersOfGroup(groupID);
    }

    /**
     * Get the user from username.
     * @param username Username of the user.
     * @return User.
     * @throws IdentityStoreException
     */
    public User getUser(String username) throws IdentityStoreException {
        return identityStoreConnector.getUser(username);
    }

    /**
     * Get the user from user Id.
     * @param userId Id of the user.
     * @return User.
     * @throws IdentityStoreException
     */
    public User getUserfromId(String userId) throws IdentityStoreException {
        return identityStoreConnector.getUserFromId(userId);
    }

    /**
     * Get the group from name.
     * @param groupName
     * @return Group
     */
    public Group getGroup(String groupName) throws IdentityStoreException {
        return identityStoreConnector.getGroup(groupName);
    }

    /**
     * Get the group from group id.
     * @param groupId Group id.
     * @return Group.
     */
    public Group getGroupFromId(String groupId) throws IdentityStoreException {
        return identityStoreConnector.getGroupById(groupId);
    }

    /**
     * Get user claim values.
     * @param userID Id of the user.
     * @return Map of user claims.
     * @throws IdentityStoreException
     */
    public Map<String, String> getUserClaimValues(String userID) throws IdentityStoreException {
        return identityStoreConnector.getUserClaimValues(userID);
    }

    /**
     * Get user's claim values for the given URIs.
     * @param userID Id of the user.
     * @param claimURIs Claim URIs.
     * @return Map of claims.
     * @throws IdentityStoreException
     */
    public Map<String, String> getUserClaimValues(String userID, List<String> claimURIs) throws IdentityStoreException {
        return identityStoreConnector.getUserClaimValues(userID, claimURIs);
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
        return identityStoreConnector.listUsers(filterPattern,  offset, length);
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
        return identityStoreConnector.listGroups(filterPattern, offset, length);
    }
}
