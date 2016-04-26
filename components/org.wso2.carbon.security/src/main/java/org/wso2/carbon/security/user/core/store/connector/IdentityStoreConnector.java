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

import org.wso2.carbon.security.user.core.bean.Group;
import org.wso2.carbon.security.user.core.bean.User;
import org.wso2.carbon.security.user.core.config.IdentityStoreConfig;
import org.wso2.carbon.security.user.core.exception.IdentityStoreException;

import java.util.List;
import java.util.Map;

/**
 * User store.
 */
public interface IdentityStoreConnector {

    /**
     * Initialize identity store by passing identity store configurations read from files.
     * @param identityStoreConfig IdentityStoreConfig for this connector.
     * @param storeId Id of this store.
     * @throws IdentityStoreException
     */
    void init(String storeId, IdentityStoreConfig identityStoreConfig) throws IdentityStoreException;

    /**
     * Get user store ID which is unique for a user store.
     * @return returns the unique id for the user store
     */
    String getIdentityStoreId();

    /**
     * Search user from user id.
     * @param userID User Id of the user
     * @return User Object with
     * @throws IdentityStoreException
     */
    User.UserBuilder getUserFromId(String userID) throws IdentityStoreException;

    /**
     * Get user from the user name.
     * @param username Name of the user.
     * @return @see User.UserBuilder.
     * @throws IdentityStoreException
     */
    User.UserBuilder getUser(String username) throws IdentityStoreException;

    /**
     * List all users in User Store according to the filter pattern.
     * @param filterPattern Filter pattern to be used.
     * @param offset        Offset to get the Users.
     * @param length        Number of users from the offset.
     * @return List of Identities which matches the given claim attribute with given filter or empty list if there are
     *         no identities to match.
     * @throws IdentityStoreException
     */
    List<User.UserBuilder> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * Retrieve attributes of the user with the given ID.
     *
     * @param userID ID of the user whose claims are requested
     * @return Attribute map of the user with given ID
     * @throws IdentityStoreException
     */
    Map<String, String> getUserAttributeValues(String userID) throws IdentityStoreException;

    /**
     * Get user attributes for given attribute names.
     * @param userID Unique id of the user.
     * @param attributeNames User attribute names.
     * @return Map of user attributes.
     * @throws IdentityStoreException
     */
    Map<String, String> getUserAttributeValues(String userID, List<String> attributeNames)
            throws IdentityStoreException;

    /**
     * Retrieve group with given group ID.
     * @param groupID Unique ID of the group
     * @return Group with the given GroupID
     * @throws IdentityStoreException
     */
    Group.GroupBuilder getGroupById(String groupID) throws IdentityStoreException;

    /**
     * Retrieve group from the group name.
     * @param groupName Name of the group
     * @return Group with the given group name.
     * @throws IdentityStoreException
     */
    Group.GroupBuilder getGroup(String groupName) throws IdentityStoreException;

    /**
     * List groups according to the filter pattern.
     * @param filterPattern Filter pattern for to list groups.
     * @param offset Offset for the group list.
     * @param length Length from the offset.
     * @return List of groups that matches the filter pattern.
     * @throws IdentityStoreException
     */
    List<Group.GroupBuilder> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * Retrieve groups of a given User with unique ID.
     * @param userID Id of the User.
     * @return List of Groups which this user is assigned to
     * @throws IdentityStoreException
     */
    List<Group.GroupBuilder> getGroupsOfUser(String userID) throws IdentityStoreException;

    /**
     * Retrieve set of users belongs to a group.
     * @param groupID Unique ID of the group
     * @return Set of IdentityObjects resides in Group
     * @throws IdentityStoreException
     */
    List<User.UserBuilder> getUsersOfGroup(String groupID) throws IdentityStoreException;

    /**
     * Checks whether the user is in the group.
     * @return true if user is in the group.
     */
    boolean isUserInGroup(String userid, String groupId) throws IdentityStoreException;

    /**
     * To check whether a user store is read only.
     * @return True if the user store is read only, unless returns false
     * @throws IdentityStoreException
     */
    boolean isReadOnly() throws IdentityStoreException;

    /**
     * Returns IdentityStoreConfig which consists of user store configurations.
     * @return @see IdentityStoreConfig which consists of user store configurations
     */
    IdentityStoreConfig getIdentityStoreConfig();
}
