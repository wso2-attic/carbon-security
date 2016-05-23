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

/**
 * Virtual identity store with the caching.
 * @since 1.0.0
 */
public class CacheBackedIdentityStore implements IdentityStore {

    private static Logger log = LoggerFactory.getLogger(CacheBackedIdentityStore.class);
    private static final boolean IS_DEBUG_ENABLED = log.isDebugEnabled();

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

        if (IS_DEBUG_ENABLED) {
            log.debug("Cache backed identity store successfully initialized.");
        }
    }

    @Override
    public User getUser(String username) throws IdentityStoreException, UserNotFoundException {

        Cache<String, User> cache = cacheManager.getCache("getUser");

        if (cache == null) {
            cache = this.createCache(String.class, User.class, "getUser");
        }

        User user = cache.get(username);

        if (user == null) {
            user = identityStore.getUser(username);
            cache.put(username, user);
        }

        return user;
    }

    @Override
    public User getUserFromId(String userId, String identityStoreId) throws IdentityStoreException {

        Cache<String, User> cache = cacheManager.getCache("getUserFromId");

        if (cache == null) {
            cache = this.createCache(String.class, User.class, "getUserFromId");
        }

        User user = cache.get(userId);

        if (user == null) {
            user = identityStore.getUserFromId(userId, identityStoreId);
            cache.put(userId, user);
        }

        return user;
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

        Cache<String, Group> cache = cacheManager.getCache("getGroup");

        if (cache == null) {
            cache = this.createCache(String.class, Group.class, "getGroup");
        }

        Group group = cache.get(groupName);

        if (group == null) {
            group = identityStore.getGroup(groupName);
            cache.put(groupName, group);
        }

        return group;
    }

    @Override
    public Group getGroupFromId(String groupId, String identityStoreId) throws IdentityStoreException {

        Cache<String, Group> cache = cacheManager.getCache("getGroupFromId");

        if (cache == null) {
            cache = this.createCache(String.class, Group.class, "getGroupFromId");
        }

        Group group = cache.get(groupId);

        if (group == null) {
            group = identityStore.getGroupFromId(groupId, identityStoreId);
            cache.put(groupId, group);
        }

        return group;
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

    private <K, V> Cache<K, V> createCache(Class<K> keyClass, Class<V> valueClass, String cacheName) {

        MutableConfiguration<K, V> configuration = new MutableConfiguration<>();
        configuration.setStoreByValue(true)
                .setTypes(keyClass, valueClass);

        return cacheManager.createCache(cacheName, configuration);
    }
}
