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

package org.wso2.carbon.security.caas.user.core.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents a virtual authorization store to abstract the underlying stores.
 * @since 1.0.0
 */
public class AuthorizationStoreImpl implements AuthorizationStore {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationStoreImpl.class);

    private RealmService realmService;
    private Map<String, AuthorizationStoreConnector> authorizationStoreConnectors = new HashMap<>();

    @Override
    public void init(RealmService realmService, Map<String, AuthorizationConnectorConfig> authorizationConnectorConfigs)
            throws AuthorizationStoreException {

        this.realmService = realmService;

        if (authorizationConnectorConfigs.isEmpty()) {
            throw new StoreException("At least one authorization store configuration must present.");
        }

        for (Map.Entry<String, AuthorizationConnectorConfig> authorizationStoreConfig :
                authorizationConnectorConfigs.entrySet()) {

            String connectorType = authorizationStoreConfig.getValue().getConnectorType();
            AuthorizationStoreConnectorFactory authorizationStoreConnectorFactory = CarbonSecurityDataHolder
                    .getInstance().getAuthorizationStoreConnectorFactoryMap().get(connectorType);

            if (authorizationStoreConnectorFactory == null) {
                throw new StoreException("No credential store connector factory found for given type.");
            }

            AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectorFactory.getInstance();
            authorizationStoreConnector.init(authorizationStoreConfig.getKey(), authorizationStoreConfig.getValue());

            authorizationStoreConnectors.put(authorizationStoreConfig.getKey(), authorizationStoreConnector);
        }

        if (log.isDebugEnabled()) {
            log.debug("Authorization store successfully initialized.");
        }
    }

    @Override
    public boolean isUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

        // Get the roles directly associated to the user.
        List<Role> roles = new ArrayList<>();
        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            roles.addAll(authorizationStoreConnector.getRolesForUser(userId, identityStoreId)
                    .stream()
                    .map(roleBuilder -> roleBuilder
                            .setAuthorizationStore(realmService.getAuthorizationStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        // Get the roles associated through groups.
        List<Group> groups = realmService.getIdentityStore().getGroupsOfUser(userId, identityStoreId);
        for (Group group : groups) {
            roles.addAll(getRolesOfGroup(group.getGroupId(), identityStoreId));
        }

        if (roles.isEmpty()) {
            throw new StoreException("No roles assigned for this user");
        }

        for (Role role : roles) {
            if (isRoleAuthorized(role.getRoleId(), role.getAuthorizationStoreId(), permission)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException {

        List<Role> roles = getRolesOfGroup(groupId, identityStoreId);

        for (Role role : roles) {
            if (isRoleAuthorized(role.getRoleId(), role.getAuthorizationStoreId(), permission)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        List<Permission.PermissionBuilder> permissionBuilders = authorizationStoreConnector
                .getPermissionsForRole(roleId);

        if (permissionBuilders.isEmpty()) {
            throw new StoreException("No permissions assigned for this role");
        }

        for (Permission.PermissionBuilder permissionBuilder : permissionBuilders) {
            if (permissionBuilder.build().getPermissionString().equals(permission.getPermissionString())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            if (authorizationStoreConnector.isUserInRole(userId, identityStoreId, roleName)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            if (authorizationStoreConnector.isGroupInRole(groupId, identityStoreId, roleName)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public Role getRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException {

        RoleNotFoundException roleNotFoundException = new RoleNotFoundException("Role not found for the given name.");

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            try {
                return authorizationStoreConnector.getRole(roleName)
                        .setAuthorizationStore(realmService.getAuthorizationStore())
                        .build();
            } catch (RoleNotFoundException e) {
                roleNotFoundException.addSuppressed(e);
            }
        }
        throw roleNotFoundException;
    }

    @Override
    public Permission getPermission(String resourceId, String action) throws PermissionNotFoundException,
            AuthorizationStoreException {

        PermissionNotFoundException permissionNotFoundException =
                new PermissionNotFoundException("Permission not found for the given resource id and the action.");

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            try {
                return authorizationStoreConnector.getPermission(resourceId, action).build();
            } catch (PermissionNotFoundException e) {
                permissionNotFoundException.addSuppressed(e);
            }
        }
        throw permissionNotFoundException;
    }

    @Override
    public List<Role> getRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException {

        List<Role> roles = new ArrayList<>();
        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            roles.addAll(authorizationStoreConnector.getRolesForUser(userId, identityStoreId)
                    .stream()
                    .map(roleBuilder -> roleBuilder.setAuthorizationStore(realmService.getAuthorizationStore()).build())
                    .collect(Collectors.toList()));
        }

        return roles;
    }

    @Override
    public List<User> getUsersOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        List<User> users = new ArrayList<>();

        // TODO: Can replace with JAVA 8 map when the carbon kernel support rethrow exceptions.
        for (User.UserBuilder userBuilder : authorizationStoreConnector.getUsersOfRole(roleId)) {
            users.add(realmService.getIdentityStore().getUserFromId(userBuilder.getUserId(),
                    userBuilder.getIdentityStoreId()));
        }

        return users;
    }

    @Override
    public List<Group> getGroupsOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        List<Group> groups = new ArrayList<>();

        // TODO: Can replace with JAVA 8 map when the carbon kernel support rethrow exceptions.
        for (Group.GroupBuilder groupBuilder : authorizationStoreConnector.getGroupsOfRole(roleId)) {
            groups.add(realmService.getIdentityStore().getGroupFromId(groupBuilder.getGroupId(),
                    groupBuilder.getIdentityStoreId()));
        }

        return groups;
    }

    @Override
    public List<Role> getRolesOfGroup(String groupId, String identityStoreId) throws AuthorizationStoreException {

        List<Role> roles = new ArrayList<>();

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            roles.addAll(authorizationStoreConnector.getRolesForGroup(groupId, identityStoreId)
                    .stream()
                    .map(roleBuilder -> roleBuilder
                            .setAuthorizationStore(realmService.getAuthorizationStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        return roles;
    }

    @Override
    public List<Permission> getPermissionsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        return authorizationStoreConnector.getPermissionsForRole(roleId)
                .stream()
                .map(Permission.PermissionBuilder::build)
                .collect(Collectors.toList());
    }

    @Override
    public Role addRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        Role.RoleBuilder roleBuilder = authorizationStoreConnector.addRole(roleName, permissions);

        if (roleBuilder == null) {
            throw new AuthorizationStoreException("Role builder is null.");
        }

        return roleBuilder.setAuthorizationStore(realmService.getAuthorizationStore()).build();
    }

    @Override
    public void deleteRole(Role role) throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors.get(role
                .getAuthorizationStoreId());

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    role.getAuthorizationStoreId()));
        }

        authorizationStoreConnector.deleteRole(role.getRoleId());
    }

    @Override
    public Permission addPermission(String resourceId, String action, String authorizationStoreId)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        return authorizationStoreConnector.addPermission(resourceId, action).build();
    }

    @Override
    public void deletePermission(Permission permission) throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(permission.getAuthorizationStoreId());

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    permission.getAuthorizationStoreId()));
        }

        authorizationStoreConnector.deletePermission(permission.getPermissionId());
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

        if (newRoleList == null || newRoleList.isEmpty()) {
            for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
                authorizationStoreConnector.updateRolesInUser(userId, identityStoreId, newRoleList);
            }
            return;
        }

        Map<String, List<Role>> roleMap = this.getRolesWithAuthorizationStore(newRoleList);

        for (Map.Entry<String, List<Role>> roleEntry : roleMap.entrySet()) {
            AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                    .get(roleEntry.getKey());
            if (authorizationStoreConnector == null) {
                throw new StoreException(String.format("No authorization store found for the given id %s",
                        roleEntry.getKey()));
            }
            authorizationStoreConnector.updateRolesInUser(userId, identityStoreId, roleEntry.getValue());
        }
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                                  List<Role> rolesToBeUnassign) throws AuthorizationStoreException {

        Map<String, List<Role>> rolesToBeAssignWithStoreId = this.getRolesWithAuthorizationStore(rolesToBeAssign);
        Map<String, List<Role>> rolesToBeUnAssignWithStoreId = this.getRolesWithAuthorizationStore(rolesToBeUnassign);

        Set<String> keys = new HashSet<>();
        keys.addAll(rolesToBeAssignWithStoreId.keySet());
        keys.addAll(rolesToBeUnAssignWithStoreId.keySet());

        for (String key : keys) {

            AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors.get(key);

            if (authorizationStoreConnector == null) {
                throw new StoreException(String.format("No authorization store found for the given id %s.", key));
            }

            authorizationStoreConnector.updateRolesInUser(userId, identityStoreId, rolesToBeAssignWithStoreId.get(key),
                    rolesToBeUnAssignWithStoreId.get(key));
        }
    }

    @Override
    public void updateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        authorizationStoreConnector.updateUsersInRole(roleId, newUserList);
    }

    @Override
    public void updateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                                  List<User> usersToBeUnassign) throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        authorizationStoreConnector.updateUsersInRole(roleId, usersToBeAssign, usersToBeUnassign);
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

        if (newRoleList == null || newRoleList.isEmpty()) {
            for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
                authorizationStoreConnector.updateRolesInGroup(groupId, identityStoreId, newRoleList);
            }
            return;
        }

        Map<String, List<Role>> roleMap = this.getRolesWithAuthorizationStore(newRoleList);

        for (Map.Entry<String, List<Role>> roleEntry : roleMap.entrySet()) {
            AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                    .get(roleEntry.getKey());
            if (authorizationStoreConnector == null) {
                throw new StoreException(String.format("No authorization store found for the given id %s",
                        roleEntry.getKey()));
            }
            authorizationStoreConnector.updateRolesInGroup(groupId, identityStoreId, roleEntry.getValue());
        }
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                                   List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {

        Map<String, List<Role>> rolesToBeAssignWithStoreId = this.getRolesWithAuthorizationStore(rolesToBeAssign);
        Map<String, List<Role>> rolesToBeUnAssignWithStoreId = this.getRolesWithAuthorizationStore(rolesToBeUnassigned);

        Set<String> keys = new HashSet<>();
        keys.addAll(rolesToBeAssignWithStoreId.keySet());
        keys.addAll(rolesToBeUnAssignWithStoreId.keySet());

        for (String key : keys) {

            AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors.get(key);

            if (authorizationStoreConnector == null) {
                throw new StoreException(String.format("No authorization store found for the given id %s.", key));
            }

            authorizationStoreConnector.updateRolesInGroup(groupId, identityStoreId,
                    rolesToBeAssignWithStoreId.get(key), rolesToBeUnAssignWithStoreId.get(key));
        }
    }

    @Override
    public void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        authorizationStoreConnector.updateGroupsInRole(roleId, newGroupList);
    }

    @Override
    public void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                                   List<Group> groupToBeUnassign) throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        authorizationStoreConnector.updateGroupsInRole(roleId, groupToBeAssign, groupToBeUnassign);
    }

    @Override
    public void updatePermissionsInRole(String roleId, String authorizationStoreId, List<Permission> newPermissionList)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        authorizationStoreConnector.updatePermissionsInRole(roleId, newPermissionList);
    }

    @Override
    public void updatePermissionsInRole(String roleId, String authorizationStoreId,
                                        List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    authorizationStoreId));
        }

        authorizationStoreConnector.updatePermissionsInRole(roleId, permissionsToBeAssign, permissionsToBeUnassign);
    }

    /**
     * Get the roles with there respective authorization store id.
     * @param roles List of roles.
     * @return Roles grouped from there authorization store id.
     */
    private Map<String, List<Role>> getRolesWithAuthorizationStore(List<Role> roles) {

        Map<String, List<Role>> roleMap = new HashMap<>();

        if (roles == null) {
            return roleMap;
        }

        for (Role role : roles) {
            List<Role> roleList = roleMap.get(role.getAuthorizationStoreId());
            if (roleList == null) {
                roleList = new ArrayList<>();
            }
            roleList.add(role);
            roleMap.put(role.getAuthorizationStoreId(), roleList);
        }

        return roleMap;
    }
}
