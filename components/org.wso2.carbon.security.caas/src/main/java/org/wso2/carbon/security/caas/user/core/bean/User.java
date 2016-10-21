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

package org.wso2.carbon.security.caas.user.core.bean;

import org.wso2.carbon.security.caas.user.core.claim.Claim;
import org.wso2.carbon.security.caas.user.core.claim.ClaimManager;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.ClaimManagerException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;

import java.util.List;

/**
 * Represents a user in the user core. All of the user related identity operations can be
 * done through this class.
 */
public class User {

    /**
     * The globally unique userId of the user.
     */
    private String userId;

    /**
     * The domain this user belongs to.
     */
    private Domain domain;

    /**
     * The IdentityStore this user originates from.
     */
    private IdentityStore identityStore;

    /**
     * The AuthorizationStore that manages permissions of this user.
     */
    private AuthorizationStore authorizationStore;

    /**
     * The ClaimManager which manages claims of this user.
     */
    private ClaimManager claimManager;

    private User(String userId, Domain domain, IdentityStore identityStore,
                 AuthorizationStore authorizationStore, ClaimManager claimManager) {

        this.userId = userId;
        this.domain = domain;
        this.identityStore = identityStore;
        this.authorizationStore = authorizationStore;
        this.claimManager = claimManager;
    }

    /**
     * Get user name.
     *
     * @return User name.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Get the user's domain.
     *
     * @return Domain of the user.
     */
    public Domain getDomain() {
        return this.domain;
    }

    /**
     * Get claims of this user.
     *
     * @return List of User claims.
     * @throws IdentityStoreException Identity store exception.
     */
    public List<Claim> getClaims() throws IdentityStoreException, ClaimManagerException {
        return claimManager.getClaims(this);
    }

    /**
     * Get claims of this user for given URIs.
     *
     * @param claimURIs Claim URIs that needs to be retrieved.
     * @return List of User claims.
     * @throws IdentityStoreException Identity store exception.
     */
    public List<Claim> getClaims(List<String> claimURIs) throws IdentityStoreException, ClaimManagerException {
        return claimManager.getClaims(this, claimURIs);
    }

    /**
     * Get the groups assigned to this user.
     *
     * @return List of Groups assigned to this user.
     * @throws IdentityStoreException Identity store exception.
     */
    public List<Group> getGroups() throws IdentityStoreException {
        return identityStore.getGroupsOfUser(userId);
    }

    /**
     * Get the roles assigned to this user.
     *
     * @return List of Roles assigned to this user.
     * @throws AuthorizationStoreException Authorization store exception,
     */
    public List<Role> getRoles() throws AuthorizationStoreException {
        return authorizationStore.getRolesOfUser(userId, domain);
    }

    /**
     * Get permissions filtered from the given resource.
     *
     * @param resource Resource to filter.
     * @return List of permissions.
     * @throws AuthorizationStoreException
     */
    public List<Permission> getPermissions(Resource resource) throws AuthorizationStoreException {
        return authorizationStore.getPermissionsOfUser(userId, domain, resource);
    }

    /**
     * Get permissions filtered from the given action.
     *
     * @param action Action to filter.
     * @return List of permissions.
     * @throws AuthorizationStoreException
     */
    public List<Permission> getPermissions(Action action) throws AuthorizationStoreException {
        return authorizationStore.getPermissionsOfUser(userId, domain, action);
    }

    /**
     * Checks whether this user is authorized for given Permission.
     *
     * @param permission Permission that should check on this user.
     * @return True if authorized.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException      Identity store exception.
     */
    public boolean isAuthorized(Permission permission) throws AuthorizationStoreException, IdentityStoreException {
        return authorizationStore.isUserAuthorized(userId, permission, domain);
    }

    /**
     * Checks whether this User is in the given Role.
     *
     * @param roleName Name of the Role.
     * @return True if this user is in the Role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public boolean isInRole(String roleName) throws AuthorizationStoreException {
        return authorizationStore.isUserInRole(userId, roleName);
    }

    /**
     * Checks whether this user is in the given Group.
     *
     * @param groupName Name of the Group.
     * @return True if this User is in the group.
     * @throws IdentityStoreException Identity store exception.
     */
    public boolean isInGroup(String groupName) throws IdentityStoreException {
        return identityStore.isUserInGroup(userId, groupName);
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     *
     * @param newRolesList List of Roles needs to be assigned to this User.
     * @throws AuthorizationStoreException Authorization store exception,
     * @throws IdentityStoreException      Identity store exception.
     */
    public void updateRoles(List<Role> newRolesList) throws AuthorizationStoreException, IdentityStoreException {
        authorizationStore.updateRolesInUser(userId, domain, newRolesList);
    }

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     *
     * @param assignList   List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    public void updateRoles(List<Role> assignList, List<Role> unAssignList) throws AuthorizationStoreException {
        authorizationStore.updateRolesInUser(userId, domain, assignList, unAssignList);
    }

    /**
     * Builder for the user bean.
     */
    public static class UserBuilder {

        private String userId;
        private Domain domain;

        private IdentityStore identityStore;
        private AuthorizationStore authorizationStore;
        private ClaimManager claimManager;

        public String getUserId() {
            return userId;
        }

        public IdentityStore getIdentityStore() {
            return identityStore;
        }

        public AuthorizationStore getAuthorizationStore() {
            return authorizationStore;
        }

        public ClaimManager getClaimManager() {
            return claimManager;
        }

        public UserBuilder setUserId(String userName) {
            this.userId = userName;
            return this;
        }

        public UserBuilder setDomain(Domain domain) {
            this.domain = domain;
            return this;
        }

        public UserBuilder setIdentityStore(IdentityStore identityStore) {
            this.identityStore = identityStore;
            return this;
        }

        public UserBuilder setAuthorizationStore(AuthorizationStore authorizationStore) {
            this.authorizationStore = authorizationStore;
            return this;
        }

        public UserBuilder setClaimManager(ClaimManager claimManager) {
            this.claimManager = claimManager;
            return this;
        }

        public User build() {

            if (userId == null || identityStore == null || authorizationStore == null || claimManager == null) {
                throw new StoreException("Required data missing for building user.");
            }

            return new User(userId, domain, identityStore, authorizationStore, claimManager);
        }
    }
}
