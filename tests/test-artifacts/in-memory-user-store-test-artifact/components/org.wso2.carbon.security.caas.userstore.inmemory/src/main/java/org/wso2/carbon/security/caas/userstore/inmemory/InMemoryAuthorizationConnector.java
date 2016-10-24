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

package org.wso2.carbon.security.caas.userstore.inmemory;

import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnector;

import java.util.List;

/**
* InMemory connector for authorization store.
* @since 1.0.0
*/
public class InMemoryAuthorizationConnector implements AuthorizationStoreConnector {

    @Override
    public void init(AuthorizationStoreConnectorConfig authorizationStoreConnectorConfig)
            throws AuthorizationStoreException {
    }

    @Override
    public String getAuthorizationStoreId() {
        return null;
    }

    @Override
    public List<Resource.ResourceBuilder> getResources(String resourcePattern) {
        return null;
    }

    @Override
    public List<Action.ActionBuilder> getActions(String actionPattern) {
        return null;
    }

    @Override
    public int getRoleCount() {
        return 0;
    }

    @Override
    public List<Role.RoleBuilder> listRoles(String filterPattern, int offset, int length) {
        return null;
    }

    @Override
    public int getPermissionCount() {
        return 0;
    }

    @Override
    public List<Permission.PermissionBuilder> listPermissions(String resourcePattern, String actionPattern, int offset,
                                                              int length) {
        return null;
    }

    @Override
    public Role.RoleBuilder getRole(String roleId) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Permission.PermissionBuilder getPermission(Resource resource, Action action)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> getRolesForUser(String userId, String identityStoreId)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> getRolesForGroup(String groupName, String identityStoreId)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Permission.PermissionBuilder> getPermissionsForRole(String roleName, Resource resource)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Permission.PermissionBuilder> getPermissionsForRole(String roleId, Action action)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Resource.ResourceBuilder addResource(String resourceNamespace, String resourceId, String userId)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Action addAction(String actionNamespace, String actionName) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Permission.PermissionBuilder addPermission(Resource resource, Action action)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Role.RoleBuilder addRole(String roleName, List<Permission> permissions)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public AuthorizationStoreConnectorConfig getAuthorizationStoreConfig() {
        return null;
    }

    @Override
    public void updateUsersInRole(String roleId, List<User> newUserList) {

    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

    }

    @Override
    public void updateGroupsInRole(String roleId, List<Group> newGroupList) {

    }

    @Override
    public void updatePermissionsInRole(String roleId, List<Permission> newPermissionList) {

    }

    @Override
    public void updatePermissionsInRole(String roleId, List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) {
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                                  List<Role> rolesToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void updateUsersInRole(String roleId, List<User> usersToBeAssign, List<User> usersToBeUnassign)
            throws AuthorizationStoreException {

    }

    @Override
    public void updateGroupsInRole(String roleId, List<Group> groupToBeAssign, List<Group> groupToBeUnassign)
            throws AuthorizationStoreException {

    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                                   List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {

    }

    @Override
    public boolean isUserInRole(String userId, String roleName) {
        return false;
    }

    @Override
    public boolean isGroupInRole(String groupId, String roleName) {
        return false;
    }

    @Override
    public List<User.UserBuilder> getUsersOfRole(String roleId) {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupsOfRole(String roleId) {
        return null;
    }

    @Override
    public void deleteRole(String roleId) {
    }

    @Override
    public void deletePermission(String permissionId) {
    }

    @Override
    public void deleteResource(Resource resource) throws AuthorizationStoreException {
    }

    @Override
    public void deleteAction(Action action) throws AuthorizationStoreException {

    }

    @Override
    public void updateRolesInUser(String userId, String identityStore, List<Role> newRoleList) {
    }
}
