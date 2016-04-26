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

package org.wso2.carbon.security.userstore.inmemory;

import org.wso2.carbon.security.user.core.bean.Permission;
import org.wso2.carbon.security.user.core.bean.Role;
import org.wso2.carbon.security.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.user.core.store.connector.AuthorizationStoreConnector;

import java.util.List;

/**
* InMemory connector for authorization store.
* @since 1.0.0
*/
public class InMemoryAuthorizationConnector implements AuthorizationStoreConnector {

    @Override
    public void init(AuthorizationStoreConfig authorizationStoreConfig) throws AuthorizationStoreException {

    }

    @Override
    public Role.RoleBuilder getRole(String roleId) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Permission getPermission(String permissionId) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> listRoles(String atribute, String filter) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Permission> listPermissions(String atribute, String filter) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> getRolesForUser(String userId) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> getRolesForGroup(String groupName) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Permission> getPermissionsForRole(String roleName) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Permission addNewPermission(String resourceId, String action) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Role.RoleBuilder addNewRole(String roleName, List<Permission> permissions)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public void assignUserRole(String userId, String roleName) throws AuthorizationStoreException {

    }

    @Override
    public void addRolePermission(String roleName, String permissionName) throws AuthorizationStoreException {

    }
}
