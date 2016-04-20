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

package org.wso2.carbon.security.usercore.connector;

import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.usercore.config.IdentityStoreConfig;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;

import java.util.List;
import java.util.Map;

/**
 * User store.
 */
public interface IdentityStoreConnector {

    /**
     * Initialize identity store by passing identity store configurations read from files.
     *
     * @param identityStoreConfig UserStoreConfigurations.
     * @throws IdentityStoreException
     */
    void init(IdentityStoreConfig identityStoreConfig) throws IdentityStoreException;

    /**
     * Get the name of the user store.
     *
     * @return Name of the user store.
     */
    String getUserStoreName();

    /**
     * Get user store ID which is unique for a user store.
     *
     * @return returns the unique id for the user store
     */
    String getUserStoreID();

    /**
     * Search user from user id.
     *
     * @param userID User Id of the user
     * @return User Object with
     * @throws IdentityStoreException
     */
    User getUserFromId(String userID) throws IdentityStoreException;

    /**
     * Get user from the user name.
     * @param username
     * @return
     * @throws IdentityStoreException
     */
    User getUser(String username) throws IdentityStoreException;

    /**
     * List all users in User Store according to the filter pattern.
     *
     * @param filterPattern Filter pattern to be used.
     * @param offset        Offset to get the Users.
     * @param length        Number of users from the offset.
     * @return List of Identities which matches the given claim attribute with given filter or empty list if there are
     *         no identities to match.
     * @throws IdentityStoreException
     */
    List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * Retrieve set of claims of the user with the given ID.
     *
     * @param userID ID of the user whose claims are requested
     * @return Claims map of the user with given ID
     * @throws IdentityStoreException
     */
    Map<String, String> getUserClaimValues(String userID) throws IdentityStoreException;

    /**
     * Get user claim values for given URIs.
     * @param userID Unique id of the user.
     * @param claimURIs claim uris.
     * @return Map of user claims.
     * @throws IdentityStoreException
     */
    Map<String, String> getUserClaimValues(String userID, List<String> claimURIs) throws IdentityStoreException;

    /**
     * Retrieve group with given group ID.
     * @param groupID Unique ID of the group
     * @return Group with the given GroupID
     * @throws IdentityStoreException
     */
    Group getGroupById(String groupID) throws IdentityStoreException;

    /**
     * Retrieve group from the group name.
     * @param groupName Name of the group
     * @return Group with the given group name.
     * @throws IdentityStoreException
     */
    Group getGroup(String groupName) throws IdentityStoreException;

    /**
     * List groups according to the filter pattern.
     * @param filterPattern Filter pattern for to list groups.
     * @param offset Offset for the group list.
     * @param length Length from the offset.
     * @return List of groups that matches the filter pattern.
     * @throws IdentityStoreException
     */
    List<Group> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * Retrieve groups of a given User with unique ID.
     * @param userID Id of the User.
     * @return List of Groups which this user is assigned to
     * @throws IdentityStoreException
     */
    List<Group> getGroupsOfUser(String userID) throws IdentityStoreException;

    /**
     * Retrieve set of users belongs to a group.
     *
     * @param groupID Unique ID of the group
     * @return Set of IdentityObjects resides in Group
     * @throws IdentityStoreException
     */
    List<User> getUsersOfGroup(String groupID) throws IdentityStoreException;

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
     * @return IdentityStoreConfig which consists of user store configurations
     */
    IdentityStoreConfig getIdentityStoreConfig();
}
