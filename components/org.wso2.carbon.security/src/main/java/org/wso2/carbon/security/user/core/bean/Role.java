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
import org.wso2.carbon.security.user.core.store.AuthorizationStore;

import java.util.List;

/**
 * Represents a Role.
 */
public class Role {

    private String roleName;
    private String roleId;
    private AuthorizationStore authorizationStore;

    private Role(String roleName, String roleId, AuthorizationStore authorizationStore) {

        this.roleName = roleName;
        this.roleId = roleId;
        this.authorizationStore = authorizationStore;
    }

    /**
     * Get the name of this Role.
     * @return Role name.
     */
    public String getName() {
        return roleName;
    }

    /**
     * Get the ID of the role.
     * @return Id of the role.
     */
    public String getRoleId() {
        return roleId;
    }

    /**
     * Get the users assigned to this role.
     * @return List of users assigned to this role.
     */
    public List<User> getUsers() {
        return authorizationStore.getUsersForRole(roleId);
    }

    /**
     * Get all Permissions assign to this Role.
     * @return List of Permission.
     */
    public List<Permission> getPermissions() {
        return authorizationStore.getPermissionsForRole(roleId);
    }

    /**
     * Get all Groups assigned to this Role.
     * @return List of Group.
     */
    public List<Group> getGroups() {
        return authorizationStore.getGroupsOfRole(roleId);
    }

    /**
     * Checks whether this Role is authorized for given Permission.
     * @param permission Permission to be checked.
     * @return True if authorized.
     */
    public boolean isAuthorized(Permission permission) throws AuthorizationException, AuthorizationStoreException {
        return authorizationStore.isRoleAuthorized(roleId, permission);
    }

    /**
     * Checks whether the User is in this Role.
     * @param userId Id of the User to be checked.
     * @return True if User exists.
     */
    public boolean hasUser(String userId) {
        return authorizationStore.isUserInRole(userId, roleName);
    }

    /**
     * Checks whether the Group is in this Role.
     * @param groupId Id of the Group to be checked.
     * @return True if the Group exists.
     */
    public boolean hasGroup(String groupId) {
        return authorizationStore.isGroupInRole(groupId, roleName);
    }

    /**
     * Add a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     * @param newPermissionList New Permission list that needs to replace the existing list.
     */
    public void updatePermissions(List<Permission> newPermissionList) {
        authorizationStore.updatePermissionsInRole(roleName, newPermissionList);
    }

    /**
     * Assign a new list of Permissions to existing list and/or un-assign Permission from existing Permission. (PATCH)
     * @param assignList List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     */
    public void updatePermissions(List<Permission> assignList, List<Permission> unAssignList) {
        authorizationStore.updatePermissionsInRole(roleName, assignList, unAssignList);
    }

    /**
     * Add a new User list by <b>replacing</b> the existing User list. (PUT)
     * @param newUserList New User list that needs to replace the existing list.
     */
    public void updateUsers(List<User> newUserList) {
        authorizationStore.updateUsersInRole(roleName, newUserList);
    }

    /**
     * Assign a new list of User to existing list and/or un-assign Permission from existing User. (PATCH)
     * @param assignList List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     */
    public void updateUsers(List<User> assignList, List<User> unAssignList) {
        authorizationStore.updateUsersInRole(roleName, assignList, unAssignList);
    }

    /**
     * Add a new Group list by <b>replacing</b> the existing Group list. (PUT)
     * @param newGroupList New Group list that needs to replace the existing list.
     */
    public void updateGroups(List<Group> newGroupList) {
        authorizationStore.updateGroupsInRole(roleName, newGroupList);
    }

    /**
     * Assign a new list of Group to existing list and/or un-assign Group from existing Group. (PATCH)
     * @param assignList List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     */
    public void updateGroups(List<Group> assignList, List<Group> unAssignList) {
        authorizationStore.updateGroupsInRole(roleName, assignList, unAssignList);
    }

    /**
     * Builder for role bean.
     */
    public static class RoleBuilder {

        private String roleName;
        private String roleId;

        private AuthorizationStore authorizationStore;

        public RoleBuilder(String roleName, String roleId) {
            this.roleName = roleName;
            this.roleId = roleId;
        }

        public RoleBuilder setAuthorizationStore(AuthorizationStore authorizationStore) {
            this.authorizationStore = authorizationStore;
            return this;
        }

        public Role build() {

            if (authorizationStore == null) {
                return null;
            }

            return new Role(roleName, roleId, authorizationStore);
        }
    }
}
