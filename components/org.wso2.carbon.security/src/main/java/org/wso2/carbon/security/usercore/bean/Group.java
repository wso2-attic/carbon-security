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

package org.wso2.carbon.security.usercore.bean;

import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.store.AuthorizationStore;
import org.wso2.carbon.security.usercore.store.IdentityStore;

import java.util.List;

/**
 * Group represents a group of users.
 */
public class Group {

    private String groupID;
    private String userStoreID;
    private String groupName;
    private IdentityStore identityStore = new IdentityStore();
    private AuthorizationStore authorizationStore = new AuthorizationStore();

    public Group(String groupID, String userStoreID, String groupName) throws IdentityStoreException {
        this.groupID = groupID;
        this.userStoreID = userStoreID;
        this.groupName = groupName;
    }

    /**
     * Get the name of the Group.
     * @return Name of the Group.
     */
    public String getName() {
        return groupName;
    }

    /**
     * Get the group id.
     * @return Group id.
     */
    public String getGroupID() {
        return groupID;
    }

    /**
     * Get the users assigned to this group.
     * @return List of users assigned to this group.
     */
    public List<User> getUsers() throws IdentityStoreException {
        return identityStore.getUsersOfGroup(groupID, userStoreID);
    }

    /**
     * Get Permissions assigned to this Group.
     * @return List of Permissions.
     */
    public List<Permission> getPermissions() {
        return authorizationStore.getPermissionsForGroup(groupID);
    }

    /**
     * Get Roles assigned to this Group.
     * @return List of Roles.
     */
    public List<Role> getRoles() throws AuthorizationStoreException {
        return authorizationStore.getRolesOfGroup(groupID);
    }

    /**
     * Checks whether this Group is authorized for given Permission.
     * @param permission Permission to be checked.
     * @return True if authorized.
     */
    public boolean isAuthorized(Permission permission) {
        return authorizationStore.isGroupAuthorized(groupID, permission);
    }

    /**
     * Checks whether the User in this Group.
     * @param userId Id of the User to be checked.
     * @return True if User is in this Group.
     */
    public boolean hasUser(String userId) throws IdentityStoreException {
        return identityStore.isUserInGroup(userId, groupID);
    }

    /**
     * Checks whether this Group has the Role.
     * @param roleName Name of the Role to be checked.
     * @return True if this Group has the Role.
     */
    public boolean hasRole(String roleName) {
        return authorizationStore.isGroupInRole(groupID, roleName);
    }

    /**
     * Add a new User list by <b>replacing</b> the existing User list. (PUT)
     * @param newUserList List of User names needs to be assigned to this Group.
     */
    public void updateUsers(List<String> newUserList) throws IdentityStoreException {
        identityStore.updateUsersInGroup(groupID, newUserList);
    }

    /**
     * Assign a new list of Users to existing list and/or un-assign Users from existing list. (PATCH)
     * @param assignList List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     */
    public void updateUsers(List<String> assignList, List<String> unAssignList) throws IdentityStoreException {
        identityStore.updateUsersInGroup(groupID, assignList, unAssignList);
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * @param newRoleList List of Roles needs to be assigned to this Group.
     */
    public void updateRoles(List<Role> newRoleList) {
        authorizationStore.updateRolesInGroup(groupID, newRoleList);
    }

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param assignList List to be added to the new list.
     * @param unAssignList List to be removed from the existing list.
     */
    public void updateRoles(List<Role> assignList, List<Role> unAssignList) {
        authorizationStore.updateRolesInGroup(groupID, assignList, unAssignList);
    }
}
