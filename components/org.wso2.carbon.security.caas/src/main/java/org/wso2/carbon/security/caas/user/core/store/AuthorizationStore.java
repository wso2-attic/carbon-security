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
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConfig;
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
public class AuthorizationStore {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationStore.class);

    private RealmService realmService;
    private Map<String, AuthorizationStoreConnector> authorizationStoreConnectors = new HashMap<>();

    /**
     * Initialize the authorization store.
     * @param realmService Parent realm service.
     * @param authorizationStoreConfigs Store configs related to the authorization store.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public void init(RealmService realmService, Map<String, AuthorizationStoreConfig> authorizationStoreConfigs)
            throws AuthorizationStoreException {

        this.realmService = realmService;

        if (authorizationStoreConfigs.isEmpty()) {
            throw new StoreException("At least one authorization store configuration must present.");
        }

        for (Map.Entry<String, AuthorizationStoreConfig> authorizationStoreConfig :
                authorizationStoreConfigs.entrySet()) {

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

    /**
     * Checks whether the given user do have the permission.
     * @param userId User id of the user.
     * @param permission Permission that needs to check on.
     * @param identityStoreId Id of the user store which this user belongs.
     * @return True if the user has required permission.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
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

    /**
     * Checks whether the group is authorized.
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param permission Permission.
     * @return True if authorized.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Checks whether role is authorized.
     * @param roleId Id of the Role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permission Permission.
     * @return True if authorized.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Checks whether the user is in the role.
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @param roleName Role name
     * @return True if user is in the role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public boolean isUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            if (authorizationStoreConnector.isUserInRole(userId, identityStoreId, roleName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks whether the group has the specific role.
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param roleName Role name.
     * @return True if group has the role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public boolean isGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        for (AuthorizationStoreConnector authorizationStoreConnector : authorizationStoreConnectors.values()) {
            if (authorizationStoreConnector.isGroupInRole(groupId, identityStoreId, roleName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the role from role name.
     * @param roleName Name of the role.
     * @return Role.
     * @throws RoleNotFoundException Role not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Get the permission from resource id and action.
     * @param resourceId Resource id of the permission.
     * @param action Action of the permission.
     * @return Permission.
     * @throws PermissionNotFoundException Permission not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Get roles assigned to the specific user.
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @return List of Roles.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Get users assigned to the specific role.
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @return List of users.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
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

    /**
     * Get the assigned groups of the specific role.
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @return List of Groups.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
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

    /**
     * Get roles for specific group.
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @return List of Roles.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Get permissions assigned to the specific role.
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @return List of Permissions.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Add a new Role.
     * @param roleName Name of the Role.
     * @param permissions List of permissions to be assign.
     * @param authorizationStoreId Id of the authorizations store where the role should be stored.
     * @return New Role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Delete an existing role.
     * @param role Role to be deleted.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public void deleteRole(Role role) throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors.get(role
                .getAuthorizationStoreId());

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    role.getAuthorizationStoreId()));
        }

        authorizationStoreConnector.deleteRole(role.getRoleId());
    }

    /**
     * Add new permission.
     * @param resourceId Resource id.
     * @param action Action name.
     * @param authorizationStoreId Id of the authorizations store where the permission should store.
     * @return Created Permission.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Delete the given permission.
     * @param permission Permission to be delete.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    public void deletePermission(Permission permission) throws AuthorizationStoreException {

        AuthorizationStoreConnector authorizationStoreConnector = authorizationStoreConnectors
                .get(permission.getAuthorizationStoreId());

        if (authorizationStoreConnector == null) {
            throw new StoreException(String.format("No authorization store found for the given id %s",
                    permission.getAuthorizationStoreId()));
        }

        authorizationStoreConnector.deletePermission(permission.getPermissionId());
    }

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * Sending a null or empty list will remove all of the roles associated with the specified user in all available
     * authorization stores.
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param newRoleList List of Roles needs to be assigned to this User.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Add a new User list by <b>replacing</b> the existing User list. (PUT)
     * Sending a null or empty list will remove all of the users associated with the specified role in specified
     * authorization store.
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newUserList New User list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Assign a new list of User to existing list and/or un-assign Permission from existing User. (PATCH)
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param usersToBeAssign List to be added to the new list.
     * @param usersToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * Sending a null or empty list will remove all of the roles associated with the specified group in all available
     * authorization stores.
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param newRoleList New Roles list that needs to be replace existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassigned List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Add a new Group list by <b>replacing</b> the existing Group list. (PUT)
     * Sending a null or empty list will remove all of the groups associated with the specified role in specified
     * authorization store.
     * @param roleId Name of role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newGroupList New Group list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Assign a new list of Group to existing list and/or un-assign Group from existing Group. (PATCH)
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param groupToBeAssign List to be added to the new list.
     * @param groupToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Add a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     * Sending a null or empty list will remove all of the permissions associated with the specified role in specified
     * authorization store.
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newPermissionList New Permission list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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

    /**
     * Assign a new list of Permissions to existing list and/or un-assign Permission from existing Permission. (PATCH)
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permissionsToBeAssign List to be added to the new list.
     * @param permissionsToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
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
