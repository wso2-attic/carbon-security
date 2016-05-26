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
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;

import java.util.List;
import java.util.Map;
import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.configuration.MutableConfiguration;
import javax.security.auth.callback.Callback;

/**
 * Virtual identity store with the caching.
 * @since 1.0.0
 */
public class CacheBackedIdentityStore implements IdentityStore {

    private static Logger log = LoggerFactory.getLogger(CacheBackedIdentityStore.class);
    private static final boolean IS_DEBUG_ENABLED = log.isDebugEnabled();

    private RealmService realmService;
    private IdentityStore identityStore = new IdentityStoreImpl();
    private CacheManager cacheManager;

    @Override
    public void init(RealmService realmService, Map<String, IdentityStoreConfig> identityStoreConfigs)
            throws IdentityStoreException {

        if (CarbonSecurityDataHolder.getInstance().getCarbonCachingService() == null) {
            throw new StoreException("Caching service is not available.");
        }

        cacheManager = CarbonSecurityDataHolder.getInstance().getCarbonCachingService().getCachingProvider()
                .getCacheManager();
        identityStore.init(realmService, identityStoreConfigs);
        this.realmService = realmService;

        if (IS_DEBUG_ENABLED) {
            log.debug("Cache backed identity store successfully initialized.");
        }
    }

    @Override
    public User getUser(String username) throws IdentityStoreException, UserNotFoundException {

        Cache<String, User.UserBuilder> cache = cacheManager.getCache("user-username", String.class,
                User.UserBuilder.class);

        if (cache == null) {
            cache = this.createCache("user-username", String.class, User.UserBuilder.class);
        }

        User.UserBuilder userBuilder = cache.get(username);

        if (userBuilder == null) {
            userBuilder = identityStore.getUser(username).getBuilder();
            cache.put(username, userBuilder);
        }

        return userBuilder.setAuthorizationStore(realmService.getAuthorizationStore())
                .setIdentityStore(realmService.getIdentityStore())
                .setClaimManager(realmService.getClaimManager())
                .build();
    }

    @Override
    public User getUser(Callback[] callbacks) throws IdentityStoreException, UserNotFoundException {

        return identityStore.getUser(callbacks);
    }

    @Override
    public User getUserFromId(String userId, String identityStoreId) throws IdentityStoreException {

        Cache<String, User.UserBuilder> cache = cacheManager.getCache("user-userid", String.class,
                User.UserBuilder.class);

        if (cache == null) {
            cache = this.createCache("user-userid", String.class, User.UserBuilder.class);
        }

        User.UserBuilder userBuilder = cache.get(userId);

        if (userBuilder == null) {
            userBuilder = identityStore.getUserFromId(userId, identityStoreId).getBuilder();
            cache.put(userId, userBuilder);
        }

        return userBuilder.setAuthorizationStore(realmService.getAuthorizationStore())
                .setIdentityStore(realmService.getIdentityStore())
                .setClaimManager(realmService.getClaimManager())
                .build();
    }

    @Override
    public List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException {
        return identityStore.listUsers(filterPattern, offset, length);
    }

    @Override
    public Map<String, String> getUserAttributeValues(String userID, String userStoreId) throws IdentityStoreException {
        return identityStore.getUserAttributeValues(userID, userStoreId);
    }

    @Override
    public Map<String, String> getUserAttributeValues(String userID, List<String> attributeNames, String userStoreId)
            throws IdentityStoreException {
        return identityStore.getUserAttributeValues(userID, attributeNames, userStoreId);
    }

    @Override
    public Group getGroup(String groupName) throws IdentityStoreException, GroupNotFoundException {

        Cache<String, Group.GroupBuilder> cache = cacheManager.getCache("group-groupname", String.class,
                Group.GroupBuilder.class);

        if (cache == null) {
            cache = this.createCache("group-groupname", String.class, Group.GroupBuilder.class);
        }

        Group.GroupBuilder groupBuilder = cache.get(groupName);

        if (groupBuilder == null) {
            groupBuilder = identityStore.getGroup(groupName).getBuilder();
            cache.put(groupName, groupBuilder);
        }

        return groupBuilder.setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build();
    }

    @Override
    public Group getGroupFromId(String groupId, String identityStoreId) throws IdentityStoreException {

        Cache<String, Group.GroupBuilder> cache = cacheManager.getCache("group-groupid", String.class,
                Group.GroupBuilder.class);

        if (cache == null) {
            cache = this.createCache("group-groupid", String.class, Group.GroupBuilder.class);
        }

        Group.GroupBuilder groupBuilder = cache.get(groupId);

        if (groupBuilder == null) {
            groupBuilder = identityStore.getGroupFromId(groupId, identityStoreId).getBuilder();
            cache.put(groupId, groupBuilder);
        }

        return groupBuilder.setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build();
    }

    @Override
    public List<Group> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException {
        return identityStore.listGroups(filterPattern, offset, length);
    }

    @Override
    public List<Group> getGroupsOfUser(String userId, String userStoreId) throws IdentityStoreException {
        return identityStore.getGroupsOfUser(userId, userStoreId);
    }

    @Override
    public List<User> getUsersOfGroup(String groupID, String userStoreId) throws IdentityStoreException {
        return identityStore.getUsersOfGroup(groupID, userStoreId);
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId, String userStoreId) throws IdentityStoreException {
        return identityStore.isUserInGroup(userId, groupId, userStoreId);
    }

    private <K, V> Cache<K, V> createCache(String cacheName, Class<K> keyClass, Class<V> valueClass) {

        MutableConfiguration<K, V> configuration = new MutableConfiguration<>();
        configuration.setStoreByValue(true)
                .setTypes(keyClass, valueClass);

        return cacheManager.createCache(cacheName, configuration);
    }
}
