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

package org.wso2.carbon.security.user.core.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.user.core.bean.Group;
import org.wso2.carbon.security.user.core.bean.Permission;
import org.wso2.carbon.security.user.core.bean.Role;
import org.wso2.carbon.security.user.core.bean.User;
import org.wso2.carbon.security.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.user.core.constant.UserStoreConstants;
import org.wso2.carbon.security.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.user.core.exception.StoreException;
import org.wso2.carbon.security.user.core.service.RealmService;
import org.wso2.carbon.security.user.core.store.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.user.core.store.connector.AuthorizationStoreConnectorFactory;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Represents a virtual authorization store to abstract the underlying stores.
 * @since 1.0.0
 */
public class AuthorizationStore {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationStore.class);

    private RealmService realmService;
    private Map<String, AuthorizationStoreConnector> authorizationStoreConnectors = new HashMap<>();

    public void init(RealmService realmService, Map<String, AuthorizationStoreConfig> authorizationStoreConfigs)
            throws AuthorizationStoreException {

        this.realmService = realmService;

        if (authorizationStoreConfigs.isEmpty()) {
            throw new StoreException("At least one authorization store configuration must present.");
        }

        for (Map.Entry<String, AuthorizationStoreConfig> authorizationStoreConfig :
                authorizationStoreConfigs.entrySet()) {

            String connectorType = (String) authorizationStoreConfig.getValue().getStoreProperties()
                    .get(UserStoreConstants.CONNECTOR_TYPE);
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

    /**
     * Checks whether the given user do have the permission.
     * @param userId User id of the user.
     * @param permission Permission that needs to check on.
     * @param userStoreId Id of the user store which this user belongs.
     * @return True if the user has required permission.
     */
    public boolean isUserAuthorized(String userId, Permission permission, String userStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

        // Get the roles directly associated to the user.
        List<Role> roles = new ArrayList<>();
        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            roles.addAll(authorizationStoreConnector.getRolesForUser(userId)
                    .stream()
                    .map(roleBuilder -> roleBuilder
                            .setAuthorizationStore(realmService.getAuthorizationStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        // Get the roles associated through groups.
        List<Group> groups = realmService.getIdentityStore().getGroupsOfUser(userId, userStoreId);
        for (Group group : groups) {
            roles.addAll(getRolesOfGroup(group.getGroupId()));
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

    /**
     * Checks whether the group is authorized.
     * @param groupId Group id.
     * @param permission Permission.
     * @return True if authorized.
     */
    public boolean isGroupAuthorized(String groupId, Permission permission) throws AuthorizationStoreException {

        List<Role> roles = getRolesOfGroup(groupId);

        for (Role role : roles) {
            if (isRoleAuthorized(role.getRoleId(), role.getAuthorizationStoreId(), permission)) {
                return true;
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
    public boolean isRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        List<Permission> permissions = authorizationStoreConnector.getPermissionsForRole(roleId);

        if (permissions.isEmpty()) {
            throw new StoreException("No permissions assigned for this role");
        }

        for (Permission rolePermission : permissions) {
            if (rolePermission.getPermissionString().equals(permission.getPermissionString())) {
                return true;
            }
        }

        return false;
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
    public List<Role> getRolesOfUser(String userId) {
        throw new NotImplementedException();
    }

    /**
     * Get users assigned to the specific role.
     * @param roleId Role id.
     * @return List of users.
     */
    public List<User> getUsersOfRole(String roleId) {
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
    public List<Role> getRolesOfGroup(String groupId) throws AuthorizationStoreException {

        List<Role> roles = new ArrayList<>();

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            roles.addAll(authorizationStoreConnector.getRolesForGroup(groupId)
                    .stream()
                    .map(roleBuilder -> roleBuilder
                            .setAuthorizationStore(realmService.getAuthorizationStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        return roles;
    }

    /**
     * Get permissions assigned to the specific role.
     * @param roleId Role id.
     * @return List of Permissions.
     */
    public List<Permission> getPermissionsOfRole(String roleId) {
        throw new NotImplementedException();
    }

    /**
     * Add a new Role.
     * @param roleName Name of the Role.
     * @param permissions List of permissions to be assign.
     * @param authorizationStoreId Id of the authorizations store where the role should be stored.
     * @return New Role.
     * @throws AuthorizationStoreException
     */
    public Role addRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new AuthorizationStoreException("Invalid authorization store id.");
        }

        Role.RoleBuilder roleBuilder = authorizationStoreConnector.addNewRole(roleName, permissions);

        if (roleBuilder == null) {
            throw new AuthorizationStoreException("Role builder is null.");
        }

        return roleBuilder.setAuthorizationStore(realmService.getAuthorizationStore()).build();
    }

    /**
     * Delete an existing role.
     * @param role Role to be deleted.
     */
    public void deleteRole(Role role) {
        throw new NotImplementedException();
    }

    /**
     * Add new permission.
     * @param resourceId Resource id.
     * @param action Action name.
     * @param authorizationStoreId Id of the authorizations store where the permission should store.
     * @return Created Permission.
     * @throws AuthorizationStoreException
     */
    public Permission addPermission(String resourceId, String action, String authorizationStoreId)
            throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(authorizationStoreId);

        if (authorizationStoreConnector == null) {
            throw new AuthorizationStoreException("Invalid authorization store id.");
        }

        return authorizationStoreConnector.addNewPermission(resourceId, action);
    }

    /**
     * Delete the given permission.
     * @param permission Permission to be delete.
     */
    public void deletePermission(Permission permission) {
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * @param userId Id of the user.
     * @param newRoleList List of Roles needs to be assigned to this User.
     */
    public void updateRolesInUser(String userId, List<Role> newRoleList) {
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
     * @param roleId Id of the role.
     * @param usersToBeAssign New User list that needs to replace the existing list.
     */
    public void updateUsersInRole(String roleId, List<User> usersToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of User to existing list and/or un-assign Permission from existing User. (PATCH)
     * @param roleId Id of the role.
     * @param usersToBeAssign List to be added to the new list.
     * @param usersToBeUnassign List to be removed from the existing list.
     */
    public void updateUsersInRole(String roleId, List<User> usersToBeAssign, List<User> usersToBeUnassign) {
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

    /**
     * Add a new Group list by <b>replacing</b> the existing Group list. (PUT)
     * @param roleId Name of role.
     * @param groupToBeAssign New Group list that needs to replace the existing list.
     */
    public void updateGroupsInRole(String roleId, List<Group> groupToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of Group to existing list and/or un-assign Group from existing Group. (PATCH)
     * @param roleId Name of the role.
     * @param groupToBeAssign List to be added to the new list.
     * @param groupToBeUnassign List to be removed from the existing list.
     */
    public void updateGroupsInRole(String roleId, List<Group> groupToBeAssign, List<Group> groupToBeUnassign) {
        throw new NotImplementedException();
    }

    /**
     * Add a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     * @param roleId Name of the role.
     * @param permissionsToBeAssign New Permission list that needs to replace the existing list.
     */
    public void updatePermissionsInRole(String roleId, List<Permission> permissionsToBeAssign) {
        throw new NotImplementedException();
    }

    /**
     * Assign a new list of Permissions to existing list and/or un-assign Permission from existing Permission. (PATCH)
     * @param roleId Name of the role.
     * @param permissionsToBeAssign List to be added to the new list.
     * @param permissionsToBeUnassign List to be removed from the existing list.
     */
    public void updatePermissionsInRole(String roleId, List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) {
        throw new NotImplementedException();
    }
}
