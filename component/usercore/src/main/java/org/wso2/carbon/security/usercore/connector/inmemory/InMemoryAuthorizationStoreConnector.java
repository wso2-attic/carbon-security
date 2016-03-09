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

package org.wso2.carbon.security.usercore.connector.inmemory;

import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.bean.Permission;
import org.wso2.carbon.security.usercore.bean.Role;
import org.wso2.carbon.security.usercore.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In memory authorization store.
 */
public class InMemoryAuthorizationStoreConnector implements AuthorizationStoreConnector {

    private Map<String, Role> roles = new HashMap<>();
    private Map<String, Permission> permissions = new HashMap<>();

    private Map<String, List<Role>> userRoles = new HashMap<>();
    private Map<String, List<Group>> roleGroup = new HashMap<>();
    private Map<String, List<Permission>> rolePermissions = new HashMap<>();

    public InMemoryAuthorizationStoreConnector() {

        roles.put("admin", new Role("admin", "1"));
        roles.put("internal/everyone", new Role("internal/everyone", "2"));

        permissions.put("/permissions/all", new Permission("/permissions/all", "read"));
        permissions.put("/permissions/login", new Permission("/permissions/login", "write"));
    }

    public void addUserRole(String userId, String roleName) throws AuthorizationStoreException {

        if (!roles.containsKey(roleName)) {
            throw new AuthorizationStoreException("Role does not exists");
        }

        if (userRoles.containsKey(userId)) {
            List<Role> rolesOfUser = userRoles.get(userId);

            for (Role role : rolesOfUser) {
                if (role.getName().equals(roleName)) {
                    throw new AuthorizationStoreException("Role already exist for user.");
                }
            }
            rolesOfUser.add(roles.get(roleName));
            userRoles.put(userId, rolesOfUser);
        } else {
            List<Role> rolesOfUser = new ArrayList<>();
            rolesOfUser.add(roles.get(roleName));
            userRoles.put(userId, rolesOfUser);
        }
    }

    @Override
    public void assignUserRole(String userId, String roleName) throws AuthorizationStoreException {
    }

    @Override
    public void addRolePermission(String roleName, String permissionName) throws AuthorizationStoreException {

        if (!roles.containsKey(roleName)) {
            throw new AuthorizationStoreException("Role does not exists");
        }

        if (!permissions.containsKey(permissionName)) {
            throw new AuthorizationStoreException("Permission does not exists");
        }

        if (rolePermissions.containsKey(roleName)) {
            List<Permission> permissionsOfRole = rolePermissions.get(roleName);

            for (Permission permission : permissionsOfRole) {
                if (permission.getPermissionString().equals(permissionName)) {
                    throw new AuthorizationStoreException("Permission already exists for the role");
                }
                permissionsOfRole.add(permissions.get(permissionName));
                rolePermissions.put(roleName, permissionsOfRole);
            }
        } else {
            List<Permission> permissionsOfRole = new ArrayList<>();
            permissionsOfRole.add(permissions.get(permissionName));
            rolePermissions.put(roleName, permissionsOfRole);
        }
    }

    @Override
    public Role getRole(String roleId) {
        return null;
    }

    @Override
    public Permission getPermission(String permissionId) {
        return null;
    }

    @Override
    public List<Role> listRoles(String attribute, String filter) {
        return null;
    }

    @Override
    public List<Permission> listPermissions(String attribute, String filter) {
        return null;
    }

    @Override
    public List<Role> getRolesForUser(String userId) {
        return userRoles.get(userId);
    }

    @Override
    public List<Role> getRolesForGroup(String roleName) {
        return null;
    }

    @Override
    public List<Permission> getPermissionsForRole(String roleName) {
        return rolePermissions.get(roleName);
    }
}
