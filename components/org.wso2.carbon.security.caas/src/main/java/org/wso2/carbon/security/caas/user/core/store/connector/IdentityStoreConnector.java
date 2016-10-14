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

package org.wso2.carbon.security.caas.user.core.store.connector;

import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;

import javax.security.auth.callback.Callback;
import java.util.List;

/**
 * User store.
 */
public interface IdentityStoreConnector {

    /**
     * Initialize identity store by passing identity store configurations read from files.
     *
     * @param identityStoreConnectorConfig IdentityStoreConnectorConfig for this connector.
     * @param storeId                      Id of this store.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void init(String storeId, IdentityStoreConnectorConfig identityStoreConnectorConfig)
            throws IdentityStoreException;

    /**
     * Get user store ID which is unique for a user store.
     *
     * @return returns the unique id for the user store
     */
    String getIdentityStoreId();

    /**
     * Get user builder from the user name.
     *
     * @param attributeName  Name of the attribute.
     * @param attributeValue Value of the attribute.
     * @return User.UserBuilder.
     * @throws UserNotFoundException  User not found exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    User.UserBuilder getUserBuilder(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreException;

    /**
     * Get user builder from callbacks.
     *
     * @param callbacks Array of callbacks.
     * @return User.UserBuilder.
     * @throws UserNotFoundException  User not found exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    User.UserBuilder getUserBuilder(Callback[] callbacks) throws UserNotFoundException, IdentityStoreException;

    /**
     * Get the count of the users available in the identity store.
     *
     * @return Number of users.
     * @throws IdentityStoreException Identity Store Exception.
     */
    int getUserCount() throws IdentityStoreException;

    /**
     * Get user builders list in User Store for the given filter pattern.
     *
     * @param attributeName Name of the attribute that should use for the filter pattern.
     * @param filterPattern Filter pattern to be used.
     * @param offset        Offset to get the Users.
     * @param length        Number of users from the offset.
     * @return List of Identities which matches the given claim attribute with given filter or empty list if there are
     * no identities to match.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<User.UserBuilder> getUserBuilderList(String attributeName, String filterPattern, int offset, int length)
            throws IdentityStoreException;

    /**
     * Get all the user builders from the identity store.
     *
     * @param attributeName Name of the attribute that should use for the filter pattern.
     * @param filterPattern Filter pattern to be used.
     * @return List of Identities which matches the given claim attribute with given filter or empty list if there are
     * no identities to match.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<User.UserBuilder> getAllUserBuilderList(String attributeName, String filterPattern)
    throws IdentityStoreException;

    /**
     * Retrieve attributes of the user with the given ID.
     *
     * @param userID ID of the user whose claims are requested
     * @return Attribute map of the user with given ID
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Attribute> getUserAttributeValues(String userID)
            throws IdentityStoreException;

    /**
     * Get user attributes for given attribute names.
     *
     * @param userID         Unique id of the user.
     * @param attributeNames User attribute names.
     * @return Map of user attributes.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Attribute> getUserAttributeValues(String userID, List<String> attributeNames)
            throws IdentityStoreException;

    /**
     * Retrieve group builder from the given attribute and the value.
     *
     * @param attributeName  Name of the attribute.
     * @param attributeValue Value of the attribute.
     * @return Group with the given group name.
     * @throws IdentityStoreException Identity Store Exception.
     */
    Group.GroupBuilder getGroupBuilder(String attributeName, String attributeValue) throws GroupNotFoundException,
            IdentityStoreException;

    /**
     * Get the count of the groups available in the identity store.
     *
     * @return Number of groups.
     * @throws IdentityStoreException Identity Store Exception.
     */
    int getGroupCount() throws IdentityStoreException;

    /**
     * Get all group builders list according to the given filter pattern.
     *
     * @param filterPattern Filter pattern for to list groups.
     * @param offset        Offset for the group list.
     * @param length        Length from the offset.
     * @return List of groups that matches the filter pattern.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length)
            throws IdentityStoreException;

    /**
     * Get all of the attributes that belongs to this group.
     *
     * @param groupId Id of the group.
     * @return Map of attributes.
     * @throws IdentityStoreException
     */
    List<Attribute> getGroupAttributeValues(String groupId)
            throws IdentityStoreException;

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
     * Retrieve group builders of a given User with unique ID.
     *
     * @param userID Id of the User.
     * @return List of Groups which this user is assigned to
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Group.GroupBuilder> getGroupBuildersOfUser(String userID) throws IdentityStoreException;

    /**
     * Retrieve list of user builders that belongs to a group.
     *
     * @param groupID Unique ID of the group
     * @return Set of IdentityObjects resides in Group
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<User.UserBuilder> getUserBuildersOfGroup(String groupID) throws IdentityStoreException;

    /**
     * Checks whether the user is in the group.
     *
     * @param userId  Id of the user.
     * @param groupId Id of the group.
     * @return true if user is in the group.
     * @throws IdentityStoreException Identity store exception.
     */
    boolean isUserInGroup(String userId, String groupId)
            throws IdentityStoreException;

    /**
     * To check whether a user store is read only.
     *
     * @return True if the user store is read only, unless returns false
     * @throws IdentityStoreException Identity Store Exception.
     */
    boolean isReadOnly()
            throws IdentityStoreException;

    /**
     * Returns IdentityStoreConnectorConfig which consists of user store configurations.
     *
     * @return IdentityStoreConnectorConfig which consists of user store configurations
     */
    IdentityStoreConnectorConfig getIdentityStoreConfig();
}
