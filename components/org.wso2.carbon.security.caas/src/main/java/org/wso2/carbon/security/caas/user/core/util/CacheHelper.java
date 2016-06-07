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

package org.wso2.carbon.security.caas.user.core.util;

import org.wso2.carbon.security.caas.user.core.config.CacheConfig;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.AccessedExpiryPolicy;
import javax.cache.expiry.Duration;

/**
 * Helper class for cache handling.
 */
public class CacheHelper {

    public static final int LOW_EXPIRE_TIME = 5;
    public static final int MEDIUM_EXPIRE_TIME = 15;
    public static final int HIGH_EXPIRE_TIME = 45;

    /**
     * Create a new cache from the given cache manager.
     * @param cacheName Name of the cache.
     * @param keyClass Type of the key class.
     * @param valueClass Type of the value class.
     * @param defaultExpiryTime Cache expire time in minutes.
     * @param cacheManager Cache manager to use to create the cache.
     * @param <K> Type of the Key.
     * @param <V> Type of the Value.
     * @return Created cache.
     */
    public static <K, V> Cache<K, V> createCache(String cacheName, Class<K> keyClass, Class<V> valueClass,
                                                 int defaultExpiryTime, Map<String, CacheConfig> cacheConfigMap,
                                                 CacheManager cacheManager) {

        Duration cacheExpiry = new Duration(TimeUnit.MINUTES, getExpireTime(cacheConfigMap, cacheName,
                defaultExpiryTime));

        boolean isStatisticsEnabled = cacheConfigMap.get(cacheName).isStatisticsEnabled();

        MutableConfiguration<K, V> configuration = new MutableConfiguration<>();
        configuration.setStoreByValue(false)
                .setTypes(keyClass, valueClass)
                .setExpiryPolicyFactory(AccessedExpiryPolicy.factoryOf(cacheExpiry))
                .setStatisticsEnabled(isStatisticsEnabled);

        return cacheManager.createCache(cacheName, configuration);
    }

    /**
     * Find whether the cache is disabled for the given cache name.
     * @param cacheConfigs Map of available cache configs.
     * @param cacheName Name of the cache to be checked.
     * @return True if cache is disabled.
     */
    public static boolean isCacheDisabled(Map<String, CacheConfig> cacheConfigs, String cacheName) {

        // The default behaviour is there will be no cache config. So default value will be null for respective
        // cache config. Cache will be enabled by default and 'enabled' property will be true by default. (Even if it
        // is not present in the config.)
        return cacheConfigs.get(cacheName) != null && !cacheConfigs.get(cacheName).isEnable();
    }

    /**
     * Get the expiry time if available for given cache. Default will be return if there is no expiry time presents at
     * the config.
     * @param cacheConfigs Map of cache configs.
     * @param cacheName Name of the cache.
     * @param defaultExpireTime Default expiry time.
     * @return Expiry time in the config or default value.
     */
    public static int getExpireTime(Map<String, CacheConfig> cacheConfigs, String cacheName, int defaultExpireTime) {

        // If there is no cache config or if there is a cache config without expire time property, we should take the
        // default value.
        return cacheConfigs.get(cacheName) == null ||
                cacheConfigs.get(cacheName).getExpireTime() == 0 ? defaultExpireTime :
                cacheConfigs.get(cacheName).getExpireTime();
    }
}
