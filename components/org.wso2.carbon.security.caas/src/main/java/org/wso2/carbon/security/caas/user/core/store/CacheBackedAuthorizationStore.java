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
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;

import java.util.List;
import java.util.Map;

/**
 * Virtual authorization store with caching.
 * @since 1.0.0
 */
public class CacheBackedAuthorizationStore implements AuthorizationStore {

    // TODO: Implement Caching.

    private static Logger log = LoggerFactory.getLogger(CacheBackedIdentityStore.class);
    private static final boolean IS_DEBUG_ENABLED = log.isDebugEnabled();

    // private RealmService realmService;
    private AuthorizationStore authorizationStore = new AuthorizationStoreImpl();
    // private CacheManager cacheManager;

    @Override
    public void init(RealmService realmService, Map<String, AuthorizationStoreConfig> authorizationStoreConfigs)
            throws AuthorizationStoreException {

        // this.realmService = realmService;
        // this.cacheManager = CarbonSecurityDataHolder.getInstance().getCarbonCachingService().getCachingProvider()
        //        .getCacheManager();
        authorizationStore.init(realmService, authorizationStoreConfigs);
    }

    @Override
    public boolean isUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {
        return authorizationStore.isUserAuthorized(userId, permission, identityStoreId);
    }

    @Override
    public boolean isGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException {
        return authorizationStore.isGroupAuthorized(groupId, identityStoreId, permission);
    }

    @Override
    public boolean isRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException {
        return authorizationStore.isRoleAuthorized(roleId, authorizationStoreId, permission);
    }

    @Override
    public boolean isUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {
        return authorizationStore.isUserInRole(userId, identityStoreId, roleName);
    }

    @Override
    public boolean isGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {
        return authorizationStore.isGroupInRole(groupId, identityStoreId, roleName);
    }

    @Override
    public Role getRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException {
        return authorizationStore.getRole(roleName);
    }

    @Override
    public Permission getPermission(String resourceId, String action) throws PermissionNotFoundException,
            AuthorizationStoreException {
        return authorizationStore.getPermission(resourceId, action);
    }

    @Override
    public List<Role> getRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException {
        return authorizationStore.getRolesOfUser(userId, identityStoreId);
    }

    @Override
    public List<User> getUsersOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException {
        return authorizationStore.getUsersOfRole(roleId, authorizationStoreId);
    }

    @Override
    public List<Group> getGroupsOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException {
        return authorizationStore.getGroupsOfRole(roleId, authorizationStoreId);
    }

    @Override
    public List<Role> getRolesOfGroup(String groupId, String identityStoreId) throws AuthorizationStoreException {
        return authorizationStore.getRolesOfGroup(groupId, identityStoreId);
    }

    @Override
    public List<Permission> getPermissionsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException {
        return authorizationStore.getPermissionsOfRole(roleId, authorizationStoreId);
    }

    @Override
    public Role addRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException {
        return authorizationStore.addRole(roleName, permissions, authorizationStoreId);
    }

    @Override
    public void deleteRole(Role role) throws AuthorizationStoreException {
        authorizationStore.deleteRole(role);
    }

    @Override
    public Permission addPermission(String resourceId, String action, String authorizationStoreId)
            throws AuthorizationStoreException {
        return authorizationStore.addPermission(resourceId, action, authorizationStoreId);
    }

    @Override
    public void deletePermission(Permission permission) throws AuthorizationStoreException {
        authorizationStore.deletePermission(permission);
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {
        authorizationStore.updateRolesInUser(userId, identityStoreId, newRoleList);
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                                  List<Role> rolesToBeUnassign) throws AuthorizationStoreException {
        authorizationStore.updateRolesInUser(userId, identityStoreId, rolesToBeAssign, rolesToBeUnassign);
    }

    @Override
    public void updateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException {
        authorizationStore.updateUsersInRole(roleId, authorizationStoreId, newUserList);
    }

    @Override
    public void updateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                                  List<User> usersToBeUnassign) throws AuthorizationStoreException {
        authorizationStore.updateUsersInRole(roleId, authorizationStoreId, usersToBeAssign, usersToBeUnassign);
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {
        authorizationStore.updateRolesInGroup(groupId, identityStoreId, newRoleList);
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                                   List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {
        authorizationStore.updateRolesInGroup(groupId, identityStoreId, rolesToBeAssign, rolesToBeUnassigned);
    }

    @Override
    public void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException {
        authorizationStore.updateGroupsInRole(roleId, authorizationStoreId, newGroupList);
    }

    @Override
    public void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                                   List<Group> groupToBeUnassign) throws AuthorizationStoreException {
        authorizationStore.updateGroupsInRole(roleId, authorizationStoreId, groupToBeAssign, groupToBeUnassign);
    }

    @Override
    public void updatePermissionsInRole(String roleId, String authorizationStoreId, List<Permission> newPermissionList)
            throws AuthorizationStoreException {
        authorizationStore.updatePermissionsInRole(roleId, authorizationStoreId, newPermissionList);
    }

    @Override
    public void updatePermissionsInRole(String roleId, String authorizationStoreId,
                                        List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {
        authorizationStore.updatePermissionsInRole(roleId, authorizationStoreId, permissionsToBeAssign,
                permissionsToBeUnassign);
    }
}
