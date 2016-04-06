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
import org.wso2.carbon.security.internal.config.StoreConfigBuilder;
import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.usercore.config.IdentityStoreConfig;
import org.wso2.carbon.security.usercore.connector.IdentityStoreConnector;
import org.wso2.carbon.security.usercore.constant.UserStoreConstants;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Represents a virtual identity store to abstract the underlying user connector.
 */
public class IdentityStore {

    private static final Logger log = LoggerFactory.getLogger(IdentityStore.class);
    private static IdentityStoreConnector identityStoreConnector;

    public void init() throws IOException, IdentityStoreException {

        IdentityStoreConfig identityStoreConfig = StoreConfigBuilder
                .buildIdentityStoreConfig(UserStoreConstants.USER_STORE_CONFIGURATION_FILE);

        // TODO: Get the store id from the configuration file.
        identityStoreConnector = CarbonSecurityDataHolder.getInstance().getIdentityStoreConnectorMap()
                .get("JDBCIdentityStore");
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

    /**
     * Add an user to the user store.
     * @param username Login name or claim that can be used to uniquely identify the user.
     * @param claims User claims.
     * @param credential User credentials.
     * @param groupList List of Groups of the user.
     * @return Added user.
     * @throws IdentityStoreException
     */
    public User addUser(String username, Map<String, String> claims, Object credential, List<String> groupList)
            throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in the this version of user core");
    }

    /**
     * Add a group to the user store.
     * @param groupName Name of the group.
     * @param users List of users to be added to this group.
     * @return Added group.
     * @throws IdentityStoreException
     */
    public Group addGroup(String groupName, List<String> users) throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Delete an existing user.
     * @param userID ID of the user.
     * @throws IdentityStoreException
     */
    public void deleteUser(String userID) throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Delete a group.
     * @param groupId ID of the Group.
     * @throws IdentityStoreException
     */
    public void deleteGroup(String groupId) throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Set user attributes.
     * @param userID User id.
     * @param attributes Attributes.
     * @throws IdentityStoreException
     */
    public void setUserAttributeValues(String userID, Map<String, String> attributes) throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Delete user attribute/s of user.
     * @param userID Id of the user.
     * @param attributes Attributes.
     * @throws IdentityStoreException
     */
    public void deleteUserAttributeValues(String userID, List<String> attributes) throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Rename the user.
     * @param userId Id of the user.
     * @param newName New name.
     */
    public void renameUser(String userId, String newName) {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Add a new Group list by <b>replacing</b> the existing group list. (PUT)
     * @param userId Id of the user.
     * @param groupsToBeAssign New group list that needs to replace the existing list.
     */
    public void updateGroupsInUser(String userId, List<String> groupsToBeAssign) throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Assign a new list of Groups to existing list and/or un-assign Groups from existing Groups. (PATCH)
     * @param userId Id of the user.
     * @param groupsToBeAssign List to be added to the new list.
     * @param groupsToBeUnAssign List to be removed from the existing list.
     */
    public void updateGroupsInUser(String userId, List<String> groupsToBeAssign, List<String> groupsToBeUnAssign)
            throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Add a new User list by <b>replacing</b> the existing User list. (PUT)
     * @param groupId Id of the group.
     * @param usersToBeAssign List of Users needs to be assigned to this Group.
     */
    public void updateUsersInGroup(String groupId, List<String> usersToBeAssign) throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }

    /**
     * Assign a new list of Users to existing list and/or un-assign Users from existing list. (PATCH)
     * @param groupId Id of the group.
     * @param usersToBeAssign List to be added to the new list.
     * @param usersToBeUnAssign List to be removed from the existing list.
     */
    public void updateUsersInGroup(String groupId, List<String> usersToBeAssign, List<String> usersToBeUnAssign)
            throws IdentityStoreException {
        throw new UnsupportedOperationException("This method is not supported in this version of user core");
    }
}
