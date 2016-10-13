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

import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.claim.Claim;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;

import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;

/**
 * Represents a virtual identity store to abstract the underlying stores.
 *
 * @since 1.0.0
 */
// TODO: Resolve username with primary / unique attribute
public interface IdentityStore {
    /**
     * Initialize the identity store instance.
     *
     * @param domainManager            DomainManager instance for which is shared by the identity store
     *                                 and the credentials store.
     * @param identityConnectorConfigs Connector configs related to the identity store.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void init(DomainManager domainManager, Map<String, IdentityStoreConnectorConfig> identityConnectorConfigs)
            throws IdentityStoreException;

    /**
     * Get the user from username.
     *
     * @param username Username of the user.
     * @return User.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws UserNotFoundException  User not found exception.
     */
    User getUser(String username) throws IdentityStoreException, UserNotFoundException;

    /**
     * Get the user from the given claim. This claim value should be unique to the user for a
     * given identity store.
     *
     * @param claim User unique claim.
     * @return User.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws UserNotFoundException  User Not Found Exception.
     */
    User getUser(Claim claim) throws IdentityStoreException, UserNotFoundException;

    /**
     * Get the user from callbacks.
     *
     * @param callbacks Callback array.
     * @return User related to the callbacks.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws UserNotFoundException  User Not Found Exception.
     */
    User getUser(Callback[] callbacks) throws IdentityStoreException, UserNotFoundException;

    /**
     * List all users in Identity Store according to the filter pattern.
     *
     * @param filterPattern Filter patter to filter users.
     * @param offset        Offset for list of users.
     * @param length        Length from the offset.
     * @return List of users match the filter pattern.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * List all users in the Identity Store according to the filter pattern given for the claim value.
     *
     * @param claim  Claim with the filter pattern.
     * @param offset Offset for list of users.
     * @param length Length from the offset.
     * @return List of users match the filter pattern.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<User> listUsers(Claim claim, int offset, int length) throws IdentityStoreException;

    /**
     * Get user attribute values.
     *
     * @param userName unique user name of the user.
     * @return Map of user attributes.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Attribute> getUserAttributeValues(String userName) throws IdentityStoreException;

    /**
     * Get user's claim values for the given URIs.
     *
     * @param userName       Name of the user.
     * @param attributeNames Attribute names.
     * @return Map of user attributes.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Attribute> getUserAttributeValues(String userName, List<String> attributeNames)
            throws IdentityStoreException;

    /**
     * Get the group from name.
     *
     * @param groupName Name of the group.
     * @return Group
     * @throws IdentityStoreException Identity Store Exception.
     * @throws GroupNotFoundException Group not found exception.
     */
    Group getGroup(String groupName) throws IdentityStoreException, GroupNotFoundException;

    Group getGroup(Claim claim) throws IdentityStoreException, GroupNotFoundException;

    /**
     * List groups according to the filter pattern.
     *
     * @param filterPattern Filter pattern for to list groups.
     * @param offset        Offset for the group list.
     * @param length        Length from the offset.
     * @return List of groups that matches the filter pattern.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Group> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * Get all of the attributes that belongs to this group.
     *
     * @param groupId Id of the group.
     * @return Map of attributes.
     * @throws IdentityStoreException
     */
    List<Attribute> getGroupAttributeValues(String groupId) throws IdentityStoreException;

    /**
     * Get attribute values for the given names in the group.
     *
     * @param groupId        Id of the group.
     * @param attributeNames List of attribute names.
     * @return Map of attributes.
     * @throws IdentityStoreException
     */
    List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames)
            throws IdentityStoreException;

    /**
     * Get the groups assigned to the specified user.
     *
     * @param userName user name of the user.
     * @return List of Group assigned to the user.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Group> getGroupsOfUser(String userName) throws IdentityStoreException;

    /**
     * Get the users assigned to the specified group.
     *
     * @param groupID Id of the group.
     * @return List of users assigned to the group.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<User> getUsersOfGroup(String groupID) throws IdentityStoreException;

    /**
     * Checks whether the user is in the group.
     *
     * @param userName user name of the user.
     * @param groupId  Id of the group.
     * @return True if the user is in the group.
     * @throws IdentityStoreException Identity Store Exception.
     */
    boolean isUserInGroup(String userName, String groupId) throws IdentityStoreException;
}
