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

import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;

import java.util.List;
import java.util.Map;

/**
 * Represents a virtual authorization store to abstract the underlying stores.
 * @since 1.0.0
 */
public interface AuthorizationStore {
    /**
     * Initialize the authorization store.
     * @param realmService Parent realm service.
     * @param authorizationConnectorConfigs Connector configs related to the authorization store.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void init(RealmService realmService, Map<String, AuthorizationConnectorConfig> authorizationConnectorConfigs)
            throws AuthorizationStoreException;

    /**
     * Checks whether the given user do have the permission.
     * @param userId User id of the user.
     * @param permission Permission that needs to check on.
     * @param identityStoreId Id of the user store which this user belongs.
     * @return True if the user has required permission.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    boolean isUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException;

    /**
     * Checks whether the group is authorized.
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param permission Permission.
     * @return True if authorized.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    boolean isGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException;

    /**
     * Checks whether role is authorized.
     * @param roleId Id of the Role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permission Permission.
     * @return True if authorized.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    boolean isRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException;

    /**
     * Checks whether the user is in the role.
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @param roleName Role name
     * @return True if user is in the role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    boolean isUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException;

    /**
     * Checks whether the group has the specific role.
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param roleName Role name.
     * @return True if group has the role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    boolean isGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException;

    /**
     * Get the role from role name.
     * @param roleName Name of the role.
     * @return Role.
     * @throws RoleNotFoundException Role not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    Role getRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException;

    /**
     * Get the permission from resource id and action.
     * @param resource Resource of the permission.
     * @param action Action of the permission.
     * @return Permission.
     * @throws PermissionNotFoundException Permission not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    Permission getPermission(String resource, String action) throws PermissionNotFoundException,
            AuthorizationStoreException;

    /**
     * Get roles assigned to the specific user.
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @return List of Roles.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    List<Role> getRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException;

    /**
     * Get users assigned to the specific role.
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @return List of users.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<User> getUsersOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException;

    /**
     * Get the assigned groups of the specific role.
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @return List of Groups.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    List<Group> getGroupsOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException;

    /**
     * Get roles for specific group.
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @return List of Roles.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    List<Role> getRolesOfGroup(String groupId, String identityStoreId) throws AuthorizationStoreException;

    /**
     * Get permissions for specific role and resource.
     * @param roleId Id of the role.
     * @param authorizationStoreId Id of the authorization store.
     * @param resource Resource.
     * @return List of permissions.
     * @throws AuthorizationStoreException
     */
    List<Permission> getPermissionsOfRole(String roleId, String authorizationStoreId, Resource resource)
            throws AuthorizationStoreException;

    /**
     * Get permissions for the specific role and action.
     * @param roleId Id of the role.
     * @param authorizationStoreId Id of the authorization store.
     * @param action Action.
     * @return List of permissions.
     * @throws AuthorizationStoreException
     */
    List<Permission> getPermissionsOfRole(String roleId, String authorizationStoreId, Action action)
            throws AuthorizationStoreException;

    /**
     * Get all permissions assigned to the specific role.
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @return List of Permissions.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    List<Permission> getPermissionsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException;

    /**
     * Get permissions of this user filtered from the given resource.
     * @param userId Id of the user.
     * @param identityStoreId Id of the identity store.
     * @param resource Resource to use for filter.
     * @return List of permissions.
     * @throws AuthorizationStoreException
     */
    List<Permission> getPermissionsOfUser(String userId, String identityStoreId, Resource resource)
            throws AuthorizationStoreException;

    /**
     * Get permissions of this user filtered from the given action.
     * @param userId Id of the user.
     * @param identityStoreId Id of the identity store.
     * @param action Action to use for filter.
     * @return List of permissions.
     * @throws AuthorizationStoreException
     */
    List<Permission> getPermissionsOfUser(String userId, String identityStoreId, Action action)
            throws AuthorizationStoreException;

    /**
     * Add a new Role to primary authorization store.
     * @param roleName Name of the Role.
     * @param permissions List of permissions to be assign.
     * @return New Role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    Role addRole(String roleName, List<Permission> permissions) throws AuthorizationStoreException;

    /**
     * Add a new Role.
     * @param roleName Name of the Role.
     * @param permissions List of permissions to be assign.
     * @param authorizationStoreId Id of the authorizations store where the role should be stored.
     * @return New Role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    Role addRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException;

    /**
     * Delete an existing role.
     * @param role Role to be deleted.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void deleteRole(Role role) throws AuthorizationStoreException;

    /**
     * Add new resource to primary authorization store.
     * @param resourceNamespace Namespace of the resource.
     * @param resourceId Id of the resource.
     * @param userId Id of the owner.
     * @param identityStoreId Identity store id if the owner.
     * @return New Resource.
     * @throws AuthorizationStoreException
     */
    Resource addResource(String resourceNamespace, String resourceId, String userId, String identityStoreId)
            throws AuthorizationStoreException;

    /**
     * Add new resource.
     * @param resourceNamespace Namespace of the resource.
     * @param resourceId Id of the resource.
     * @param authorizationStoreId Id of the authorization store.
     * @param userId Id of the owner.
     * @param identityStoreId Identity store id if the owner.
     * @return New Resource.
     * @throws AuthorizationStoreException
     */
    Resource addResource(String resourceNamespace, String resourceId, String authorizationStoreId, String userId,
                         String identityStoreId) throws AuthorizationStoreException;

    /**
     * Add new action to primary authorization store.
     * @param actionNamespace Namespace of the action.
     * @param actionName Name of the action.
     * @return New action.
     * @throws AuthorizationStoreException
     */
    Action addAction(String actionNamespace, String actionName) throws AuthorizationStoreException;

    /**
     * Add new action.
     * @param actionNamespace Namespace of the action.
     * @param actionName Name of the action.
     * @param authorizationStoreId Id of the authorization store.
     * @return New action.
     * @throws AuthorizationStoreException
     */
    Action addAction(String actionNamespace, String actionName, String authorizationStoreId)
            throws AuthorizationStoreException;

    /**
     * Add new permission to primary authorization store.
     * @param resource Resource.
     * @param action Action.
     * @return Created Permission.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    Permission addPermission(Resource resource, Action action) throws AuthorizationStoreException;

    /**
     * Add new permission.
     * @param resource Resource.
     * @param action Action.
     * @param authorizationStoreId Id of the authorizations store where the permission should store.
     * @return Created Permission.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    Permission addPermission(Resource resource, Action action, String authorizationStoreId)
            throws AuthorizationStoreException;

    /**
     * Delete the given permission.
     * @param permission Permission to be delete.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void deletePermission(Permission permission) throws AuthorizationStoreException;

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * Sending a null or empty list will remove all of the roles associated with the specified user in all available
     * authorization stores.
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param newRoleList List of Roles needs to be assigned to this User.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                           List<Role> rolesToBeUnassign) throws AuthorizationStoreException;

    /**
     * Add a new User list by <b>replacing</b> the existing User list. (PUT)
     * Sending a null or empty list will remove all of the users associated with the specified role in specified
     * authorization store.
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newUserList New User list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException;

    /**
     * Assign a new list of User to existing list and/or un-assign Permission from existing User. (PATCH)
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param usersToBeAssign List to be added to the new list.
     * @param usersToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                           List<User> usersToBeUnassign) throws AuthorizationStoreException;

    /**
     * Add a new Role list by <b>replacing</b> the existing Role list. (PUT)
     * Sending a null or empty list will remove all of the roles associated with the specified group in all available
     * authorization stores.
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param newRoleList New Roles list that needs to be replace existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Assign a new list of Roles to existing list and/or un-assign Roles from existing list. (PATCH)
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassigned List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                            List<Role> rolesToBeUnassigned) throws AuthorizationStoreException;

    /**
     * Add a new Group list by <b>replacing</b> the existing Group list. (PUT)
     * Sending a null or empty list will remove all of the groups associated with the specified role in specified
     * authorization store.
     * @param roleId Name of role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newGroupList New Group list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException;

    /**
     * Assign a new list of Group to existing list and/or un-assign Group from existing Group. (PATCH)
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param groupToBeAssign List to be added to the new list.
     * @param groupToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                            List<Group> groupToBeUnassign) throws AuthorizationStoreException;

    /**
     * Add a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     * Sending a null or empty list will remove all of the permissions associated with the specified role in specified
     * authorization store.
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newPermissionList New Permission list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updatePermissionsInRole(String roleId, String authorizationStoreId, List<Permission> newPermissionList)
            throws AuthorizationStoreException;

    /**
     * Assign a new list of Permissions to existing list and/or un-assign Permission from existing Permission. (PATCH)
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permissionsToBeAssign List to be added to the new list.
     * @param permissionsToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void updatePermissionsInRole(String roleId, String authorizationStoreId,
                                 List<Permission> permissionsToBeAssign,
                                 List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException;
}
