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

package org.wso2.carbon.security.caas.internal.config;

import java.util.List;
import java.util.Properties;

/**
 * StoreConfig Bean
 *
 * @since 1.0.0
 */
public class StoreConfigEntry {

    // This variable represents whether cache should be enabled for a particular store. The default values is set to
    // enableCache=true unless specified otherwise in the store-config file.
    private boolean enableCache = true;

    private String connector;

    private Properties properties;

    private List<CacheEntry> caches;

    public List<CacheEntry> getCaches() {
        return caches;
    }

    public void setCaches(List<CacheEntry> cache) {
        this.caches = cache;
    }

    public boolean isEnableCache() {
        return enableCache;
    }

    public void setEnableCache(boolean enableCache) {
        this.enableCache = enableCache;
    }

    public String getConnector() {
        return connector;
    }

    public void setConnector(String connector) {
        this.connector = connector;
    }

    public Properties getProperties() {
        return properties;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }
}

