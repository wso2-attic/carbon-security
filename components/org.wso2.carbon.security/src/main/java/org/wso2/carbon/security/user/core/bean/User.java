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

package org.wso2.carbon.security.user.core.bean;

import org.wso2.carbon.security.user.core.exception.AuthorizationException;
import org.wso2.carbon.security.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.user.core.store.AuthorizationStore;
import org.wso2.carbon.security.user.core.store.IdentityStore;

import java.util.List;
import java.util.Map;

/**
 * Represents a user in the user core. All of the user related identity operations can be
 * done through this class.
 */
public class User {

    private String userID;
    private String userStoreID;
    private long tenantId;
    private String userName;

    private IdentityStore identityStore;
    private AuthorizationStore authorizationStore;

    private User(String userName, String userID, String userStoreID, long tenantId, IdentityStore identityStore,
                AuthorizationStore authorizationStore) {

        this.userID = userID;
        this.userStoreID = userStoreID;
        this.userName = userName;
        this.tenantId = tenantId;
        this.identityStore = identityStore;
        this.authorizationStore = authorizationStore;
    }

    /**
     * Get the fully qualified name of this user.
     * @return Fully qualified name as a String.
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Get user id.
     * @return User id.
     */
    public String getUserId() {
        return userID;
    }

    /**
     * Get user store id.
     * @return User store id.
     */
    public String getUserStoreId() {
        return userStoreID;
    }

    /**
     * Get tenant id.
     * @return Tenant id.
     */
    public long getTenantId() {
        return tenantId;
    }

    /**
     * Get claims of this user.
     * @return Map of User claims.
     * @throws IdentityStoreException
     */
    public Map<String, String> getClaims() throws IdentityStoreException {
        return identityStore.getUserClaimValues(userID, userStoreID);
    }

    /**
     * Get claims of this user for given URIs.
     * @param claimURIs Claim URIs that needs to be retrieved.
     * @return Map of User claims.
     * @throws IdentityStoreException
     */
    public Map<String, String> getClaims(List<String> claimURIs) throws IdentityStoreException {
        return identityStore.getUserClaimValues(userID, claimURIs, userStoreID);
    }

    /**
     * Get the groups assigned to this user.
     * @return List of Groups assigned to this user.
     * @throws IdentityStoreException
     */
    public List<Group> getGroups() throws IdentityStoreException {
        return identityStore.getGroupsOfUser(userID, userStoreID);
    }

    /**
     * Get the roles assigned to this user.
     * @return List of Roles assigned to this user.
     */
    public List<Role> getRoles() {
        return authorizationStore.getRolesForUser(userID);
    }

    /**
     * Checks whether this user is authorized for given Permission.
     * @param permission Permission that should check on this user.
     * @return True if authorized.
     * @throws AuthorizationException
     */
    public boolean isAuthorized(Permission permission) throws AuthorizationException, AuthorizationStoreException,
            IdentityStoreException {
        return authorizationStore.isUserAuthorized(userID, permission, userStoreID);
    }

    /**
     * Checks whether this User is in the given Role.
     * @param roleName Name of the Role.
     * @return True if this user is in the Role.
     */
    public boolean isInRole(String roleName) {
        return authorizationStore.isUserInRole(userID, roleName);
    }

    /**
     * Checks whether this user is in the given Group.
     * @param groupName Name of the Group.
     * @return True if this User is in the group.
     */
    public boolean isInGroup(String groupName) throws IdentityStoreException {
        return identityStore.isUserInGroup(userID, groupName, userStoreID);
    }

    /**
     * Rename this user.
     * @param newUsername New user name.
     */
    public void rename(String newUsername) {
        throw new UnsupportedOperationException("This operation is not supported in platform level.");
    }

    /**
     * Set claims for this User.
     * @param claims List of claims to be set.
     */
    public void setClaims(Map<String, String> claims) throws IdentityStoreException {
        throw new UnsupportedOperationException("This operation is not supported in platform level.");
    }

    /**
     * Add a new Group list by <b>replacing</b> the existing group list. (PUT)
     * @param newGroupList New group list names that needs to replace the existing list.
     */
    public void updateGroups(List<String> newGroupList) throws IdentityStoreException {
        throw new UnsupportedOperationException("This operation is not supported in platform level.");
    }

    /**
     * Assign a new list of Groups to existing list and/or un-assign Groups from existing Groups. (PATCH)
     * @param assignList List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     */
    public void updateGroups(List<String> assignList, List<String> unAssignList) throws IdentityStoreException {
        throw new UnsupportedOperationException("This operation is not supported in platform level.");
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * @param newRolesList List of Roles needs to be assigned to this User.
     */
    public void updateRoles(List<Role> newRolesList) {
        authorizationStore.updateRolesInUser(userID, newRolesList);
    }

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param assignList List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     */
    public void updateRoles(List<Role> assignList, List<Role> unAssignList) {
        authorizationStore.updateRolesInUser(userID, assignList, unAssignList);
    }

    /**
     * Builder for user bean.
     */
    public static class UserBuilder {

        private String userName;
        private String userId;
        private String userStoreId;
        private long tenantId;

        private IdentityStore identityStore;
        private AuthorizationStore authorizationStore;

        public UserBuilder(String userName, String userId, String userStoreId, long tenantId) {
            this.userName = userName;
            this.userId = userId;
            this.userStoreId = userStoreId;
            this.tenantId = tenantId;
        }

        public UserBuilder setIdentityStore(IdentityStore identityStore) {
            this.identityStore = identityStore;
            return this;
        }

        public UserBuilder setAuthorizationStore(AuthorizationStore authorizationStore) {
            this.authorizationStore = authorizationStore;
            return this;
        }

        public User build() {

            if (identityStore == null || authorizationStore == null) {
                return null;
            }
            return new User(userName, userId, userStoreId, tenantId, identityStore, authorizationStore);
        }
    }
}
