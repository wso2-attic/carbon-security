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
import org.wso2.carbon.kernel.utils.LambdaExceptionUtils;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.CacheConfig;
import org.wso2.carbon.security.caas.user.core.constant.CacheNames;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.util.CacheHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.cache.Cache;
import javax.cache.CacheManager;

/**
 * Virtual authorization store with caching.
 * @since 1.0.0
 */
public class CacheBackedAuthorizationStore implements AuthorizationStore {

    private static final Logger log = LoggerFactory.getLogger(CacheBackedIdentityStore.class);

    private Map<String, CacheConfig> cacheConfigs;
    private RealmService realmService;
    private AuthorizationStore authorizationStore = new AuthorizationStoreImpl();
    private CacheManager cacheManager;

    public CacheBackedAuthorizationStore(Map<String, CacheConfig> cacheConfigs) {
        this.cacheConfigs = cacheConfigs;
    }

    @Override
    public void init(RealmService realmService, Map<String, AuthorizationConnectorConfig> authorizationConnectorConfigs)
            throws AuthorizationStoreException {

        this.cacheManager = CarbonSecurityDataHolder.getInstance().getCarbonCachingService().getCachingProvider()
                .getCacheManager();
        this.realmService = realmService;
        authorizationStore.init(realmService, authorizationConnectorConfigs);

        // Initialize all caches.
        CacheHelper.createCache(CacheNames.ROLE_ROLENAME, String.class, Role.class, CacheHelper.MEDIUM_EXPIRE_TIME,
                cacheConfigs, cacheManager);
        CacheHelper.createCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class, List.class,
                CacheHelper.LOW_EXPIRE_TIME, cacheConfigs, cacheManager);
        CacheHelper.createCache(CacheNames.ROLES_GROUPID_IDENTITYSTOREID, String.class, List.class,
                CacheHelper.LOW_EXPIRE_TIME, cacheConfigs, cacheManager);
        CacheHelper.createCache(CacheNames.PERMISSION_REOURCEID_ACTION, String.class, Permission.class,
                CacheHelper.MEDIUM_EXPIRE_TIME, cacheConfigs, cacheManager);
        CacheHelper.createCache(CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID, String.class, List.class,
                CacheHelper.LOW_EXPIRE_TIME, cacheConfigs, cacheManager);

        if (log.isDebugEnabled()) {
            log.debug("Cache backed authorization store initialized successfully.");
        }
    }

    @Override
    public boolean isUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID) ||
                CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_GROUPID_IDENTITYSTOREID)) {
            return authorizationStore.isUserAuthorized(userId, permission, identityStoreId);
        }

        List<Role> roles = new ArrayList<>();

        // Get roles directly associated to the user.
        roles.addAll(getRolesOfUser(userId, identityStoreId));

        // Get roles associated through groups.
        realmService.getIdentityStore().getGroupsOfUser(userId, identityStoreId)
                .stream()
                .map(LambdaExceptionUtils.rethrowFunction(group -> roles.addAll(getRolesOfGroup(group.getGroupId(),
                        group.getIdentityStoreId()))));

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

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_GROUPID_IDENTITYSTOREID)) {
            return authorizationStore.isGroupAuthorized(groupId, identityStoreId, permission);
        }

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

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID)) {
            return authorizationStore.isRoleAuthorized(roleId, authorizationStoreId, permission);
        }

        Cache<String, List> cache = cacheManager.getCache(CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID,
                String.class, List.class);

        boolean isRoleAuthorized = false;

        List<Permission> permissions = cache.get(roleId + authorizationStoreId);
        if (permissions == null) {
            isRoleAuthorized = authorizationStore.isRoleAuthorized(roleId, authorizationStoreId, permission);
        } else {
            // Do the the logic here if there are permissions in the cache.
            for (Permission perm : permissions) {
                if (perm.equals(permission)) {
                    isRoleAuthorized = true;
                    break;
                }
            }
        }

        return isRoleAuthorized;
    }

    @Override
    public boolean isUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID)) {
            return authorizationStore.isUserInRole(userId, identityStoreId, roleName);
        }

        Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class,
                List.class);

        boolean isUserInRole = false;

        List<Role> roles = cache.get(userId + identityStoreId);
        if (roles == null) {
            isUserInRole = authorizationStore.isUserInRole(userId, identityStoreId, roleName);
        } else {
            // If there are roles for this user id and identity store id in the cache,
            // do the validation logic here.
            for (Role role : roles) {
                if (role.getName().equals(roleName)) {
                    isUserInRole = true;
                    break;
                }
            }
        }

        return isUserInRole;
    }

    @Override
    public boolean isGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_GROUPID_IDENTITYSTOREID)) {
            return authorizationStore.isGroupInRole(groupId, identityStoreId, roleName);
        }

        Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_GROUPID_IDENTITYSTOREID, String.class,
                List.class);

        boolean isGroupInRole = false;

        List<Role> roles = cache.get(groupId + identityStoreId);
        if (roles == null) {
            isGroupInRole = authorizationStore.isGroupInRole(groupId, identityStoreId, roleName);
        } else {
            // If there are roles for this group id and identity store id in the cache,
            // do the validation logic here.
            for (Role role : roles) {
                if (role.getName().equals(roleName)) {
                    isGroupInRole = true;
                    break;
                }
            }
        }

        return isGroupInRole;
    }

    @Override
    public Role getRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLE_ROLENAME)) {
            return authorizationStore.getRole(roleName);
        }

        Cache<String, Role> cache = cacheManager.getCache(CacheNames.ROLE_ROLENAME, String.class,
                Role.class);
        Role role = cache.get(roleName);

        if (role == null) {
            role = authorizationStore.getRole(roleName);
            cache.put(roleName, role);
            if (log.isDebugEnabled()) {
                log.debug("Role cached for role name: {}.", roleName);
            }
        }

        return role;
    }

    @Override
    public Permission getPermission(Resource resource, Action action) throws PermissionNotFoundException,
            AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.PERMISSION_REOURCEID_ACTION)) {
            return authorizationStore.getPermission(resource, action);
        }

        Cache<String, Permission> cache = cacheManager.getCache(CacheNames.PERMISSION_REOURCEID_ACTION, String.class,
                Permission.class);
        Permission permission = cache.get(resource.getResourceString() + action.getActionString());

        if (permission == null) {
            permission = authorizationStore.getPermission(resource, action);
            cache.put(resource.getResourceString() + action.getActionString(), permission);
            if (log.isDebugEnabled()) {
                log.debug("Permission cached for resource id: {} and action: {}.", resource.getResourceString(),
                        action.getActionString());
            }
        }

        return permission;
    }

    @Override
    public List<Role> getRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID)) {
            return authorizationStore.getRolesOfUser(userId, identityStoreId);
        }

        Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class,
                List.class);

        List<Role> roles = cache.get(userId + identityStoreId);

        if (roles == null) {
            roles = authorizationStore.getRolesOfUser(userId, identityStoreId);
            cache.put(userId + identityStoreId, roles);
            if (log.isDebugEnabled()) {
                log.debug("Roles cached for user id: {} and identity store id: {}.", userId, identityStoreId);
            }
        }

        return roles;
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

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_GROUPID_IDENTITYSTOREID)) {
            return authorizationStore.getRolesOfGroup(groupId, identityStoreId);
        }

        Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_GROUPID_IDENTITYSTOREID, String.class,
                List.class);

        List<Role> roles = cache.get(groupId + identityStoreId);

        if (roles == null) {
            roles = authorizationStore.getRolesOfUser(groupId, identityStoreId);
            if (roles != null && !roles.isEmpty()) {
                cache.put(groupId + identityStoreId, roles);
                if (log.isDebugEnabled()) {
                    log.debug("Roles cached for group id: {} and for identity store id: {}.", groupId, identityStoreId);
                }
            }
        }

        return roles;
    }

    @Override
    public List<Permission> getPermissionsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID)) {
            return authorizationStore.getPermissionsOfRole(roleId, authorizationStoreId);
        }

        Cache<String, List> cache = cacheManager.getCache(CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID,
                String.class, List.class);

        List<Permission> permissions = cache.get(roleId + authorizationStoreId);

        if (permissions == null) {
            permissions = authorizationStore.getPermissionsOfRole(roleId, authorizationStoreId);
            if (permissions != null && !permissions.isEmpty()) {
                cache.put(roleId + authorizationStoreId, permissions);
                if (log.isDebugEnabled()) {
                    log.debug("Permissions cached for role id: {} authorization store id: {}.", roleId,
                            authorizationStoreId);
                }
            }
        }

        return permissions;
    }

    @Override
    public Role addRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLE_ROLENAME)) {
            return authorizationStore.addRole(roleName, permissions, authorizationStoreId);
        }

        Cache<String, Role> cache = cacheManager.getCache(CacheNames.ROLE_ROLENAME, String.class, Role.class);

        Role role = authorizationStore.addRole(roleName, permissions, authorizationStoreId);
        cache.put(roleName, role);

        if (log.isDebugEnabled()) {
            log.debug("Role cached for role name: {}.", roleName);
        }

        return role;
    }

    @Override
    public void deleteRole(Role role) throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLE_ROLENAME)) {
            authorizationStore.deleteRole(role);
            return;
        }

        Cache<String, Role> cache = cacheManager.getCache(CacheNames.ROLE_ROLENAME, String.class, Role.class);
        cache.remove(role.getName());

        if (log.isDebugEnabled()) {
            log.debug("Role with name : {} removed from the cache.", role.getName());
        }

        authorizationStore.deleteRole(role);
    }

    @Override
    public Permission addPermission(Resource resource, Action action, String authorizationStoreId)
            throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.PERMISSION_REOURCEID_ACTION)) {
            return authorizationStore.addPermission(resource, action, authorizationStoreId);
        }

        Cache<String, Permission> cache = cacheManager.getCache(CacheNames.PERMISSION_REOURCEID_ACTION, String.class,
                Permission.class);

        Permission permission = authorizationStore.addPermission(resource, action, authorizationStoreId);
        cache.put(resource.getResourceString() + action.getActionString(), permission);

        if (log.isDebugEnabled()) {
            log.debug("permissions cached for resource id: {} and action: {}", resource, action);
        }

        return permission;
    }

    @Override
    public void deletePermission(Permission permission) throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.PERMISSION_REOURCEID_ACTION)) {
            authorizationStore.deletePermission(permission);
            return;
        }

        Cache<String, Permission> cache = cacheManager.getCache(CacheNames.PERMISSION_REOURCEID_ACTION, String.class,
                Permission.class);
        cache.remove(permission.getPermissionString());

        if (log.isDebugEnabled()) {
            log.debug("Permissions with permissions string: {} removed from the cache.",
                    permission.getPermissionString());
        }

        authorizationStore.deletePermission(permission);
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

        authorizationStore.updateRolesInUser(userId, identityStoreId, newRoleList);

        if (!CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID)) {
            Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class,
                    List.class);
            cache.put(userId + identityStoreId, newRoleList);
            if (log.isDebugEnabled()) {
                log.debug("Roles added to the cache for user id: {} and identity store id: {}.", userId,
                        identityStoreId);
            }
        }
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                                  List<Role> rolesToBeUnassign) throws AuthorizationStoreException {

        authorizationStore.updateRolesInUser(userId, identityStoreId, rolesToBeAssign, rolesToBeUnassign);

        if (!CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID)) {
            Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class,
                    List.class);
            cache.remove(userId + identityStoreId);
            if (log.isDebugEnabled()) {
                log.debug("Roles removed from cache with user id: {} and identity store id: {}", userId,
                        identityStoreId);
            }
        }
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

        if (!CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_GROUPID_IDENTITYSTOREID)) {
            Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_GROUPID_IDENTITYSTOREID, String.class,
                    List.class);
            cache.put(groupId + identityStoreId, newRoleList);
            if (log.isDebugEnabled()) {
                log.debug("Roles added to the cache for group id: {} identity store id: {}", groupId, identityStoreId);
            }
        }
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                                   List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {

        authorizationStore.updateRolesInGroup(groupId, identityStoreId, rolesToBeAssign, rolesToBeUnassigned);

        if (!CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_GROUPID_IDENTITYSTOREID)) {
            Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_GROUPID_IDENTITYSTOREID, String.class,
                    List.class);
            cache.remove(groupId + identityStoreId);
            if (log.isDebugEnabled()) {
                log.debug("Roles removed with group id: {} and identity store id: {}.", groupId, identityStoreId);
            }
        }
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

        if (!CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID)) {
            Cache<String, List> cache = cacheManager.getCache(CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID,
                    String.class, List.class);
            cache.put(roleId + authorizationStoreId, newPermissionList);
            if (log.isDebugEnabled()) {
                log.debug("Permissions cached for role id: {} and authorization store id: {}.", roleId,
                        authorizationStoreId);
            }
        }
    }

    @Override
    public void updatePermissionsInRole(String roleId, String authorizationStoreId,
                                        List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {

        authorizationStore.updatePermissionsInRole(roleId, authorizationStoreId, permissionsToBeAssign,
                permissionsToBeUnassign);

        if (!CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID)) {
            Cache<String, List> cache = cacheManager.getCache(CacheNames.PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID,
                    String.class, List.class);
            cache.remove(roleId + authorizationStoreId);
            if (log.isDebugEnabled()) {
                log.debug("Permissions removed with role id: {} and authorization store id: {}.", roleId,
                        authorizationStoreId);
            }
        }
    }
}
