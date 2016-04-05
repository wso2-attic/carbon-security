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

package org.wso2.carbon.security.usercore.connector;

import org.wso2.carbon.security.usercore.bean.Permission;
import org.wso2.carbon.security.usercore.bean.Role;
import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;

import java.util.List;

/**
 * Authorization store.
 */
public interface AuthorizationStoreConnector {

    /**
     * Get the role of from role id.
     * @param roleId Id of the Role
     * @return Role.
     */
    public Role getRole(String roleId);

    /**
     * Get permission from the permission id.
     * @param permissionId Id of the permission.
     * @return Permission.
     */
    public Permission getPermission(String permissionId);

    /**
     * List the roles.
     * @param atribute
     * @param filter
     * @return
     */
    public List<Role> listRoles(String atribute, String filter);

    /**
     * List the permissions.
     * @param atribute
     * @param filter
     * @return
     */
    public List<Permission> listPermissions(String atribute, String filter);

    /**
     * Get roles for the user id.
     * @param userId User id of the user.
     * @return Roles associated to the user.
     */
    public List<Role> getRolesForUser(String userId);

    /**
     * Get roles associated to the group.
     * @param roleName Role name of the role.
     * @return Roles associated to the group.
     */
    public List<Role> getRolesForGroup(String roleName);

    /**
     * Get permissions associated to the role.
     * @param roleName Role name of the required role.
     * @return List of permissions associated to the user.
     */
    public List<Permission> getPermissionsForRole(String roleName);

    /**
     * Add a user against a role.
     * @param userId Id of the user.
     * @param roleName Name of the role.
     */
    public void assignUserRole(String userId, String roleName) throws AuthorizationStoreException;

    /**
     * Add a permission to a role.
     * @param roleName Name of the role.
     * @param permissionName Name of the permission.
     * @throws AuthorizationStoreException
     */
    public void addRolePermission(String roleName, String permissionName) throws AuthorizationStoreException;
}
