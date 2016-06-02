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
import org.wso2.carbon.security.caas.user.core.config.CacheConfig;
import org.wso2.carbon.security.caas.user.core.constant.CacheNames;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.util.CacheHelper;

import java.util.List;
import java.util.Map;
import javax.cache.Cache;
import javax.cache.CacheManager;

/**
 * Virtual authorization store with caching.
 * @since 1.0.0
 */
public class CacheBackedAuthorizationStore implements AuthorizationStore {

    // TODO: Implement Caching.

    private static Logger log = LoggerFactory.getLogger(CacheBackedIdentityStore.class);
    private static final boolean IS_DEBUG_ENABLED = log.isDebugEnabled();
    private Map<String, CacheConfig> cacheConfigs;

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
        authorizationStore.init(realmService, authorizationConnectorConfigs);
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

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID)) {
            return authorizationStore.isUserInRole(userId, identityStoreId, roleName);
        }

        Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class,
                List.class);

        boolean isUserInRole = false;
        if (cache == null) {
            isUserInRole = authorizationStore.isUserInRole(userId, identityStoreId, roleName);
        } else {
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
        if (cache == null) {
            isGroupInRole = authorizationStore.isGroupInRole(groupId, identityStoreId, roleName);
        } else {
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
        }

        return isGroupInRole;
    }

    @Override
    public Role getRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException {

        Cache<String, Role> cache = cacheManager.getCache("role-rolename", String.class,
                Role.class);
        Role role = null;

        if (cache == null) {
            cache = CacheHelper.createCache("role-rolename", String.class, Role.class,
                    CacheHelper.MEDIUM_EXPIRE_TIME, cacheManager);
        } else {
            role = cache.get(roleName);
        }

        if (role == null) {
            role = authorizationStore.getRole(roleName);
            cache.put(roleName, role);
        }

        return role;
    }

    @Override
    public Permission getPermission(String resourceId, String action) throws PermissionNotFoundException,
            AuthorizationStoreException {

        Cache<String, Permission> cache = cacheManager.getCache("permission-resourceid-action",
                String.class, Permission.class);
        Permission permission = null;

        if (cache == null) {
            cache = CacheHelper.createCache("permission-resourceid-action", String.class,
                    Permission.class, CacheHelper.MEDIUM_EXPIRE_TIME, cacheManager);
        } else {
            permission = cache.get(resourceId + action);
        }

        if (permission == null) {
            permission = authorizationStore.getPermission(resourceId, action);
            cache.put(resourceId + action, permission);
        }

        return permission;
    }

    @Override
    public List<Role> getRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException {

        if (CacheHelper.isCacheDisabled(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID)) {
            return authorizationStore.getRolesOfUser(userId, identityStoreId);
        }

        int expireTime = CacheHelper.getExpireTime(cacheConfigs, CacheNames.ROLES_USERID_IDENTITYSTOREID,
                CacheHelper.LOW_EXPIRE_TIME);

        Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class,
                List.class);

        List<Role> roles = null;
        if (cache == null) {
            cache = CacheHelper.createCache(CacheNames.ROLES_USERID_IDENTITYSTOREID, String.class, List.class,
                    expireTime, cacheManager);
        } else {
            roles = cache.get(userId + identityStoreId);
        }

        if (roles == null) {
            roles = authorizationStore.getRolesOfUser(userId, identityStoreId);
            cache.put(userId + identityStoreId, roles);
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

        int expireTime = CacheHelper.getExpireTime(cacheConfigs, CacheNames.ROLES_GROUPID_IDENTITYSTOREID,
                CacheHelper.LOW_EXPIRE_TIME);

        Cache<String, List> cache = cacheManager.getCache(CacheNames.ROLES_GROUPID_IDENTITYSTOREID, String.class,
                List.class);

        List<Role> roles = null;
        if (cache == null) {
            cache = CacheHelper.createCache(CacheNames.ROLES_GROUPID_IDENTITYSTOREID, String.class, List.class,
                    expireTime, cacheManager);
        } else {
            roles = cache.get(groupId + identityStoreId);
        }

        if (roles == null) {
            roles = authorizationStore.getRolesOfUser(groupId, identityStoreId);
            cache.put(groupId + identityStoreId, roles);
        }

        return roles;
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
