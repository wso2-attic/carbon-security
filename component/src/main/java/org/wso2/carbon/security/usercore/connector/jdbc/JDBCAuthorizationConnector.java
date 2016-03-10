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

package org.wso2.carbon.security.usercore.connector.jdbc;

import org.wso2.carbon.security.usercore.bean.Permission;
import org.wso2.carbon.security.usercore.bean.Role;
import org.wso2.carbon.security.usercore.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.usercore.exception.AuthorizationStoreException;

import java.util.List;

/**
 * JDBC connector for authorization store.
 */
public class JDBCAuthorizationConnector implements AuthorizationStoreConnector {

    @Override
    public Role getRole(String roleId) {
        return null;
    }

    @Override
    public Permission getPermission(String permissionId) {
        return null;
    }

    @Override
    public List<Role> listRoles(String atribute, String filter) {
        return null;
    }

    @Override
    public List<Permission> listPermissions(String atribute, String filter) {
        return null;
    }

    @Override
    public List<Role> getRolesForUser(String userId) {
        return null;
    }

    @Override
    public List<Role> getRolesForGroup(String roleName) {
        return null;
    }

    @Override
    public List<Permission> getPermissionsForRole(String roleName) {
        return null;
    }

    @Override
    public void assignUserRole(String userId, String roleName) throws AuthorizationStoreException {

    }

    @Override
    public void addRolePermission(String roleName, String permissionName) throws AuthorizationStoreException {

    }
}
