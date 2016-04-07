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
import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.bean.Permission;
import org.wso2.carbon.security.usercore.bean.Role;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.usercore.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.usercore.exception.AuthorizationException;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.List;

/**
 * Connector for the Authorization store.
 */
public class AuthorizationStore {

    private static Logger log = LoggerFactory.getLogger(AuthorizationStore.class);
    private AuthorizationStoreConnector authorizationStore;

    public AuthorizationStore() {

        // TODO: Get the store id from the configuration file.
        authorizationStore = CarbonSecurityDataHolder.getInstance().getAuthorizationStoreConnectorMap()
                .get("JDBCAuthorizationStore");
    }

    /**
     * Checks whether the given user do have the permission.
     * @param userId User id of the user.
     * @param permission Permission that needs to check on.
     * @return True if the user has required permission.
     */
    public boolean isUserAuthorized(String userId, Permission permission) throws AuthorizationException {

        List<Role> roles = authorizationStore.getRolesForUser(userId);
        if (roles == null) {
            throw new AuthorizationException("No roles assigned for this user");
        }

        for (Role role : roles) {
            List<Permission> permissions = authorizationStore.getPermissionsForRole(role.getName());
            if (permissions == null) {
                continue;
            }
            for (Permission rolePermission : permissions) {
                if (rolePermission.getPermissionString().equals(permission.getPermissionString())) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks whether role is authorized.
     * @param roleId Id of the Role.
     * @param permission Permission.
     * @return True if authorized.
     */
    public boolean isRoleAuthorized(String roleId, Permission permission) throws AuthorizationException {

        Role role = authorizationStore.getRole(roleId);

        List<Permission> permissions = authorizationStore.getPermissionsForRole(role.getName());

        if (permissions == null) {
            throw new AuthorizationException("No permissions assigned for this role");
        }

        for (Permission rolePermission : permissions) {
            if (rolePermission.getPermissionString().equals(permission.getPermissionString())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether the group is authorized.
     * @param groupId Group id.
     * @param permission Permission.
     * @return True if authorized.
     */
    public boolean isGroupAuthorized(String groupId, Permission permission) {
        throw new NotImplementedException();
    }

    /**
     * Checks whether the user is in the role.
     * @param userId User id.
     * @param roleName Role name
     * @return True if user is in the role.
     */
    public boolean isUserInRole(String userId, String roleName) {
        throw new NotImplementedException();
    }

    /**
     * Checks whether the group has the specific role.
     * @param groupId Group id.
     * @param roleName Role name.
     * @return True if group has the role.
     */
    public boolean isGroupInRole(String groupId, String roleName) {
        throw new NotImplementedException();
    }

    /**
     * Get roles assigned to the specific user.
     * @param userId User id.
     * @return List of Roles.
     */
    public List<Role> getRolesForUser(String userId) {
        throw new NotImplementedException();
    }

    /**
     * Get users assigned to the specific role.
     * @param roleId Role id.
     * @return List of users.
     */
    public List<User> getUsersForRole(String roleId) {
        throw new NotImplementedException();
    }

    /**
     * Get the assigned groups of the specific role.
     * @param roleId Role id.
     * @return List of Groups.
     */
    public List<Group> getGroupsOfRole(String roleId) {
        throw new NotImplementedException();
    }

    /**
     * Get roles for specific group.
     * @param groupId Group id.
     * @return List of Roles.
     */
    public List<Role> getRolesOfGroup(String groupId) {
        throw new NotImplementedException();
    }

    /**
     * Get permissions assigned to the specific role.
     * @param roleId Role id.
     * @return List of Permissions.
     */
    public List<Permission> getPermissionsForRole(String roleId) {
        throw new NotImplementedException();
    }

    /**
     * Get permissions assigned to the specific group.
     * @param groupId Group id.
     * @return List of Permissions.
     */
    public List<Permission> getPermissionsForGroup(String groupId) {
        throw new NotImplementedException();
    }

    /**
     * Add a new Role.
     * @param roleName Name of the Role.
     * @param permissions List of permissions to be assign.
     * @return New Role.
     */
    public Role addRole(String roleName, List<Permission> permissions) {
        throw new NotImplementedException();
    }

    /**
     * Delete an existing role.
     * @param role Role to be deleted.
     */
    public void deleteRole(Role role) {
        throw new NotImplementedException();
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * @param userId Id of the user.
     * @param rolesToBeAssign List of Roles needs to be assigned to this User.
     */
    public void updateRolesInUser(String userId, List<Role> rolesToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param userId Id of the user.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassign List to be removed from the existing list.
     */
    public void updateRolesInUser(String userId, List<Role> rolesToBeAssign, List<Role> rolesToBeUnassign) {
        throw new NotImplementedException();
    }

    /**
     * Add a new User list by <b>replacing</b> the existing User list. (PUT)
     * @param roleName Name of the role.
     * @param usersToBeAssign New User list that needs to replace the existing list.
     */
    public void updateUsersInRole(String roleName, List<User> usersToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of User to existing list and/or un-assign Permission from existing User. (PATCH)
     * @param roleName Name of the role.
     * @param usersToBeAssign List to be added to the new list.
     * @param usersToBeUnassign List to be removed from the existing list.
     */
    public void updateUsersInRole(String roleName, List<User> usersToBeAssign, List<User> usersToBeUnassign) {
        throw new NotImplementedException();
    }

    /**
     * Add a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     * @param roleName Name of the role.
     * @param permissionsToBeAssign New Permission list that needs to replace the existing list.
     */
    public void updatePermissionsInRole(String roleName, List<Permission> permissionsToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of Permissions to existing list and/or un-assign Permission from existing Permission. (PATCH)
     * @param roleName Name of the role.
     * @param permissionsToBeAssign List to be added to the new list.
     * @param permissionsToBeUnassign List to be removed from the existing list.
     */
    public void updatePermissionsInRole(String roleName, List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) {
        throw new NotImplementedException();
    }

    /**
     * Add a new Group list by <b>replacing</b> the existing Group list. (PUT)
     * @param roleName Name of role.
     * @param groupToBeAssign New Group list that needs to replace the existing list.
     */
    public void updateGroupsInRole(String roleName, List<Group> groupToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of Group to existing list and/or un-assign Group from existing Group. (PATCH)
     * @param roleName Name of the role.
     * @param groupToBeAssign List to be added to the new list.
     * @param groupToBeUnassign List to be removed from the existing list.
     */
    public void updateGroupsInRole(String roleName, List<Group> groupToBeAssign, List<Group> groupToBeUnassign) {
        throw new NotImplementedException();
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * @param groupId Id of the group.
     * @param rolesToBeAssign List of Roles needs to be assigned to this Group.
     */
    public void updateRolesInGroup(String groupId, List<Role> rolesToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param groupId Id of the group.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassign List to be removed from the existing list.
     */
    public void updateRolesInGroup(String groupId, List<Role> rolesToBeAssign, List<Role> rolesToBeUnassign) {
        throw new NotImplementedException();
    }
}
