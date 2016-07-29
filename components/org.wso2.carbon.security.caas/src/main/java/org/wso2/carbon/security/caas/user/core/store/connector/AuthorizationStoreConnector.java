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

import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;

import java.util.List;

/**
 * Authorization store.
 */
public interface AuthorizationStoreConnector {

    /**
     * Initialize the authorization store.
     * @param storeId Id of this store.
     * @param authorizationConnectorConfig Authorization store configurations for this connector.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void init(String storeId, AuthorizationConnectorConfig authorizationConnectorConfig)
            throws AuthorizationStoreException;

    /**
     * Get the role of from role id.
     * @param roleId Id of the Role
     * @return Role.RoleBuilder.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    Role.RoleBuilder getRole(String roleId) throws RoleNotFoundException, AuthorizationStoreException;

    /**
     * Get permission from the resource id and action.
     * @param resource Resource of this permission.
     * @param action Action of the permission.
     * @return Permission.PermissionBuilder.
     * @throws AuthorizationStoreException Authorization Store Exception
     */
    Permission.PermissionBuilder getPermission(Resource resource, Action action) throws PermissionNotFoundException,
            AuthorizationStoreException;

    /**
     * Get roles for the user id.
     * @param userId User id of the user.
     * @param identityStoreId Identity Store id of the user.
     * @return Roles associated to the user.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    List<Role.RoleBuilder> getRolesForUser(String userId, String identityStoreId) throws AuthorizationStoreException;

    /**
     * Get roles associated to the group.
     * @param groupName Name of the group.
     * @param identityStoreId Identity Store id of the user.
     * @return Roles associated to the group.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    List<Role.RoleBuilder> getRolesForGroup(String groupName, String identityStoreId)
            throws AuthorizationStoreException;

    /**
     * Get permissions associated to the role.
     * @param roleId Role id of the required role.
     * @param resource Resource which the permissions should take.
     * @return List of permissions associated to the Role.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    List<Permission.PermissionBuilder> getPermissionsForRole(String roleId, Resource resource)
            throws AuthorizationStoreException;

    /**
     * Get permissions associated to the role.
     * @param roleId Role id of the required role.
     * @param action Action which the permissions should take.
     * @return List of permissions associated to the Role.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    List<Permission.PermissionBuilder> getPermissionsForRole(String roleId, Action action)
            throws AuthorizationStoreException;

    /**
     * Add new permission.
     * @param resource Resource.
     * @param action Action.
     * @return New permission.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    Permission.PermissionBuilder addPermission(Resource resource, Action action) throws AuthorizationStoreException;

    /**
     * Add new role.
     * @param roleName Name of the new role.
     * @param permissions List of permissions to be assign.
     * @return New Role.RoleBuilder.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    Role.RoleBuilder addRole(String roleName, List<Permission> permissions) throws AuthorizationStoreException;

    /**
     * Checks whether the users is in the role.
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param roleName Name of the role.
     * @return True if user is in the role.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    boolean isUserInRole(String userId, String identityStoreId, String roleName) throws AuthorizationStoreException;

    /**
     * Checks whether the group is in the role.
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param roleName Name of the role.
     * @return True if the group is in the role.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    boolean isGroupInRole(String groupId, String identityStoreId, String roleName) throws AuthorizationStoreException;

    /**
     * Get the users of the role.
     * @param roleId Id of the role.
     * @return List of @see User.UserBuilder.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    List<User.UserBuilder> getUsersOfRole(String roleId) throws AuthorizationStoreException;

    /**
     * Get the groups of the role.
     * @param roleId Id of the role.
     * @return List of @see Group.GroupBuilder.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    List<Group.GroupBuilder> getGroupsOfRole(String roleId) throws AuthorizationStoreException;

    /**
     * Delete the specified role.
     * @param roleId Id of the role.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void deleteRole(String roleId) throws AuthorizationStoreException;

    /**
     * Delete the specified permission.
     * @param permissionId Id of the permission.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void deletePermission(String permissionId) throws AuthorizationStoreException;

    /**
     * Update the roles of the user by replacing existing roles. (PUT)
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param newRoleList Role list to replace the existing.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Get the authorization store config.
     * @return AuthorizationConnectorConfig.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    AuthorizationConnectorConfig getAuthorizationStoreConfig() throws AuthorizationStoreException;

    /**
     * Add a new User list by <b>replacing</b> the existing User list. (PUT)
     * @param roleId Id of the role.
     * @param newUserList New user list.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateUsersInRole(String roleId, List<User> newUserList) throws AuthorizationStoreException;

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * @param groupId Id of the group.
     * @param identityStoreId Id of the identity store.
     * @param newRoleList List
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Add a new Group list by <b>replacing</b> the existing Group list. (PUT)
     * @param roleId Id of the role.
     * @param newGroupList New group list.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateGroupsInRole(String roleId, List<Group> newGroupList) throws AuthorizationStoreException;

    /**
     * Add a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     * @param roleId Id of the role.
     * @param newPermissionList New permissions list.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updatePermissionsInRole(String roleId, List<Permission> newPermissionList) throws AuthorizationStoreException;

    /**
     * Assign a new list of Permissions to existing list and/or un-assign Permission from existing Permission. (PATCH)
     * @param roleId Id of the role.
     * @param permissionsToBeAssign List of permissions to be assign.
     * @param permissionsToBeUnassign List of permissions to be un assign.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updatePermissionsInRole(String roleId, List<Permission> permissionsToBeAssign,
                                 List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException;

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param userId Id of the user.
     * @param identityStoreId Id of the identity store.
     * @param rolesToBeAssign List of roles to be assign.
     * @param rolesToBeUnassign List of roles to be un assign.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                           List<Role> rolesToBeUnassign) throws AuthorizationStoreException;

    /**
     * Assign a new list of User to existing list and/or un-assign Permission from existing User. (PATCH)
     * @param roleId Id of the role.
     * @param usersToBeAssign List of users to be assign.
     * @param usersToBeUnassign List of users to un assign.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateUsersInRole(String roleId, List<User> usersToBeAssign, List<User> usersToBeUnassign)
            throws AuthorizationStoreException;

    /**
     * Assign a new list of Group to existing list and/or un-assign Group from existing Group. (PATCH)
     * @param roleId Id of the role.
     * @param groupToBeAssign List of groups to be assign.
     * @param groupToBeUnassign List of groups to be un assign.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateGroupsInRole(String roleId, List<Group> groupToBeAssign, List<Group> groupToBeUnassign)
            throws AuthorizationStoreException;

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param groupId Id of the group.
     * @param identityStoreId Id of the identity store of the group.
     * @param rolesToBeAssign List of roles to be assign.
     * @param rolesToBeUnassigned List of roles to be un assign.
     * @throws AuthorizationStoreException Authorization Store Exception.
     */
    void updateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                            List<Role> rolesToBeUnassigned) throws AuthorizationStoreException;

    /**
     * Get the id of this authorization store.
     * @return Id of the authorization store.
     */
    String getAuthorizationStoreId();
}
