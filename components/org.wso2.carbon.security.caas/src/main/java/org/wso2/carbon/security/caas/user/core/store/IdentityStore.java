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

import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.claim.Claim;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaim;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;

import java.util.List;

/**
 * Represents a virtual identity store to abstract the underlying stores.
 *
 * @since 1.0.0
 */

public interface IdentityStore {

    /**
     * Initialize IdentityStore with {@link DomainManager} instance.
     *
     * @param domainManager    Active {@link DomainManager} intance
     * @throws IdentityStoreException
     */
    void init(DomainManager domainManager)
            throws IdentityStoreException;

    /**
     * Retrieve a user by global unique Id.
     *
     * @param userId    Global Unique Id
     * @return User object
     * @throws IdentityStoreException
     * @throws UserNotFoundException
     */
    User getUser(String userId) throws IdentityStoreException, UserNotFoundException;

    /**
     * Retrieve a user by global unique Id.
     *
     * @param userId The globally unique user Id
     * @param domain The domain the user is in
     * @return User
     * @throws IdentityStoreException
     * @throws UserNotFoundException
     */
    User getUser(String userId, String domain) throws IdentityStoreException, UserNotFoundException;

    /**
     * Retrieve a user by claim.
     *
     * @param claim Populated claim
     * @return User object
     * @throws IdentityStoreException
     * @throws UserNotFoundException
     */
    User getUser(Claim claim) throws IdentityStoreException, UserNotFoundException;

    /**
     * Retrieve a user by claim from a specific domain.
     *
     * @param claim Populated claim
     * @param domainName Domain name to retrieve user from
     * @return User object
     * @throws IdentityStoreException
     * @throws UserNotFoundException
     */
    User getUser(Claim claim, String domainName) throws IdentityStoreException, UserNotFoundException;

    /**
     * List a set of users selected from the given range.
     *
     * @param offset Start position
     * @param length Number of users to retrieve
     * @return A list of users within given range
     * @throws IdentityStoreException
     */
    List<User> listUsers(int offset, int length) throws IdentityStoreException;

    /**
     * List a set of users selected from a specific domain for a given range
     *
     * @param offset Start position
     * @param length Number of users to retrieve
     * @param domainName The domain name to retrieve users from
     * @return A list of users within given range selected from the given domain
     * @throws IdentityStoreException
     */
    List<User> listUsers(int offset, int length, String domainName) throws IdentityStoreException;

    /**
     * List a set of users that matches a given claim.
     *
     * @param claim Populated claim
     * @param offset Start position
     * @param length Number of users to retrieve
     * @return List of users
     * @throws IdentityStoreException
     */
    List<User> listUsers(Claim claim, int offset, int length) throws IdentityStoreException;

    /**
     * List a set of users that matches a given claim in a specific domain.
     *
     * @param claim Populated claim
     * @param offset Start position
     * @param length Number of Users to retrieve
     * @param domain The domain to retrieve users from
     * @return List of users
     * @throws IdentityStoreException
     */
    List<User> listUsers(Claim claim, int offset, int length, String domain) throws IdentityStoreException;

    List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length)
            throws IdentityStoreException;

    List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length, String domain)
            throws IdentityStoreException;

    /**
     * Retrieve group from group Id.
     *
     * @param groupId The Id of the group
     * @return Group
     * @throws IdentityStoreException
     * @throws GroupNotFoundException
     */
    Group getGroup(String groupId) throws IdentityStoreException, GroupNotFoundException;

    /**
     * Get group from group Id from a specific domain.
     *
     * @param groupId The Id of the group
     * @param domain The domain to retrieve group from
     * @return Group
     * @throws IdentityStoreException
     * @throws GroupNotFoundException
     */
    Group getGroup(String groupId, String domain) throws IdentityStoreException, GroupNotFoundException;

    /**
     * Get group that matches a claim.
     *
     * @param claim Populated claim
     * @return Group
     * @throws IdentityStoreException
     * @throws GroupNotFoundException
     */
    Group getGroup(Claim claim) throws IdentityStoreException, GroupNotFoundException;

    /**
     * Get group that matches a claim from a specific domain.
     * @param claim Populated claim
     * @param domain The domain to retrieve groups from
     * @return
     * @throws IdentityStoreException
     * @throws GroupNotFoundException
     */
    Group getGroup(Claim claim, String domain) throws IdentityStoreException, GroupNotFoundException;

    /**
     * List groups from a given range.
     *
     * @param offset Start position
     * @param length Number of groups to retrieve
     * @return List of groups within given range
     * @throws IdentityStoreException
     */
    List<Group> listGroups(int offset, int length) throws IdentityStoreException;

    /**
     * List groups from a given range for a given domain.
     *
     * @param offset Start position
     * @param length Number of groups to retrieve
     * @param domain The domain to retrieve groups from
     * @return List of groups within given range in the given domain
     * @throws IdentityStoreException
     */
    List<Group> listGroups(int offset, int length, String domain) throws IdentityStoreException;

    /**
     * List groups that matches a given claim in a given range.
     *
     * @param claim Populated claim
     * @param offset Start position
     * @param length Number of groups to retrieve
     * @return List of groups that matches the given claim in the given range
     * @throws IdentityStoreException
     */
    List<Group> listGroups(Claim claim, int offset, int length) throws IdentityStoreException;

    /**
     * List groups that matches a given claim in a given range for a specific domain.
     *
     * @param claim Populated claim
     * @param offset Start position
     * @param length Number of groups to retrieve
     * @param domain The domain to retrieve groups from
     * @return List of groups that matches the given claim in the given range in the given domain
     * @throws IdentityStoreException
     */
    List<Group> listGroups(Claim claim, int offset, int length, String domain) throws IdentityStoreException;

    List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length)
            throws IdentityStoreException;

    List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length, String domain)
            throws IdentityStoreException;

    /**
     * Get list of groups a user belongs to.
     *
     * @param userId The Id of the user
     * @return List of groups the user is in
     * @throws IdentityStoreException
     */
    List<Group> getGroupsOfUser(String userId) throws IdentityStoreException;

    /**
     * Get list of users in a given group.
     *
     * @param groupId The group to find users of
     * @return List of users contained in the group
     * @throws IdentityStoreException
     */
    List<User> getUsersOfGroup(String groupId) throws IdentityStoreException;

    /**
     * Get list of groups a user belongs to in a specific domain.
     *
     * @param userId The Id of the user
     * @param domain The domain the users belongs to
     * @return List of groups the user is in
     * @throws IdentityStoreException
     */
    List<Group> getGroupsOfUser(String userId, String domain) throws IdentityStoreException;

    /**
     * Get list of users in a given group for a specific domain.
     *
     * @param groupId The group to find users of
     * @param domain The domain the user belongs to
     * @return List of users contained in the group
     * @throws IdentityStoreException
     */
    List<User> getUsersOfGroup(String groupId, String domain) throws IdentityStoreException;

    /**
     * Check if a user belongs to a given group.
     *
     * @param userId The user Id
     * @param groupId The group Id
     * @return True if user belongs to the given group
     * @throws IdentityStoreException
     */
    boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException;

    /**
     * Check if a user belongs to a given group in a specific domain.
     *
     * @param userId The user Id
     * @param groupId The group Id
     * @param domain The domain the user and the group belongs to
     * @return True if user belongs to the given group
     * @throws IdentityStoreException
     */
    boolean isUserInGroup(String userId, String groupId, String domain) throws IdentityStoreException;

    /**
     * Get all claims of a user.
     *
     * @param user The user to retrieve claims for
     * @return List of claims
     * @throws IdentityStoreException
     */
    List<Claim> getClaims(User user) throws IdentityStoreException;

    /**
     * Get all claims of a user for given URIs.
     *
     * @param user The user to retrieve claims for
     * @param claimURIs List of claimURIs to retrieve claims for
     * @return List of claims
     * @throws IdentityStoreException
     */
    List<Claim> getClaims(User user, List<String> claimURIs) throws IdentityStoreException;

}
