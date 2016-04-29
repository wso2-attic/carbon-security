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

import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;

import java.util.List;

/**
 * Authorization store.
 */
public interface AuthorizationStoreConnector {

    /**
     * Initialize the authorization store.
     * @param storeId Id of this store.
     * @param authorizationStoreConfig Authorization store configurations for this connector.
     * @throws AuthorizationStoreException
     */
    void init(String storeId, AuthorizationStoreConfig authorizationStoreConfig) throws AuthorizationStoreException;

    /**
     * Get the id of this authorization store.
     * @return Id of the authorization store.
     */
    String getAuthorizationStoreId();

    /**
     * Get the role of from role id.
     * @param roleId Id of the Role
     * @return Role.
     */
    Role.RoleBuilder getRole(String roleId) throws AuthorizationStoreException;

    /**
     * Get permission from the permission id.
     * @param permissionId Id of the permission.
     * @return Permission.
     */
    Permission.PermissionBuilder getPermission(String permissionId) throws AuthorizationStoreException;

    /**
     * Get roles for the user id.
     * @param userId User id of the user.
     * @return Roles associated to the user.
     */
    List<Role.RoleBuilder> getRolesForUser(String userId, String identityStoreId) throws AuthorizationStoreException;

    /**
     * Get roles associated to the group.
     * @param groupName Name of the group.
     * @return Roles associated to the group.
     */
    List<Role.RoleBuilder> getRolesForGroup(String groupName, String identityStoreId)
            throws AuthorizationStoreException;

    /**
     * Get permissions associated to the role.
     * @param roleName Role name of the required role.
     * @return List of permissions associated to the user.
     */
    List<Permission.PermissionBuilder> getPermissionsForRole(String roleName) throws AuthorizationStoreException;

    /**
     * Add new permission.
     * @param resourceId Resource id.
     * @param action Action name.
     * @return New permission.
     * @throws AuthorizationStoreException
     */
    Permission.PermissionBuilder addPermission(String resourceId, String action) throws AuthorizationStoreException;

    /**
     * Add new role.
     * @param roleName Name of the new role.
     * @param permissions List of permissions to be assign.
     * @return New Role.
     * @throws AuthorizationStoreException
     */
    Role.RoleBuilder addRole(String roleName, List<Permission> permissions) throws AuthorizationStoreException;

    /**
     * Add a user against a role.
     * @param userId Id of the user.
     * @param roleName Name of the role.
     */
    void assignUserRole(String userId, String roleName) throws AuthorizationStoreException;

    /**
     * Add a permission to a role.
     * @param roleName Name of the role.
     * @param permissionName Name of the permission.
     * @throws AuthorizationStoreException
     */
    void addRolePermission(String roleName, String permissionName) throws AuthorizationStoreException;

    /**
     * Get the authorization store config.
     * @return @see AuthorizationStoreConfig.
     */
    AuthorizationStoreConfig getAuthorizationStoreConfig();

    /**
     * Checks whether the users is in the role.
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param roleName Name of the role.
     * @return True if user is in the role.
     */
    boolean isUserInRole(String userId, String identityStoreId, String roleName);

    /**
     * Checks whether the group is in the role.
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param roleName Name of the role.
     * @return True if the group is in the role.
     */
    boolean isGroupInRole(String groupId, String identityStoreId, String roleName);

    /**
     * Get the users of the role.
     * @param roleId Id of the role.
     * @return List of @see User.UserBuilder.
     */
    List<User.UserBuilder> getUsersOfRole(String roleId);

    /**
     * Get the groups of the role.
     * @param roleId Id of the role.
     * @return List of @see Group.GroupBuilder.
     */
    List<Group.GroupBuilder> getGroupsOfRole(String roleId);

    /**
     * Delete the specified role.
     * @param roleId Id of the role.
     */
    void deleteRole(String roleId);

    /**
     * Delete the specified permission.
     * @param permissionId Id of the permission.
     */
    void deletePermission(String permissionId);

    /**
     * Update the roles of the user by replacing existing roles. (PUT)
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param newRoleList Role list to replace the existing.
     */
    void updateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList);
}
