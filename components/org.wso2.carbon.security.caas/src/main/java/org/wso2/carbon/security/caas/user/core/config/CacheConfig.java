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

package org.wso2.carbon.security.caas.user.core.config;

/**
 * Represents a cache config in the store config.
 */
public class CacheConfig {

    private int expireTime;
    private int maxCapacity;

    // Cache entries for a particular store should be enabled by default hence setting the value true by default so the
    // cache config will always be enable=true if a value is not provided for a cache entry in store-config file.
    private boolean enable = true;
    private boolean statisticsEnabled;

    public boolean isEnable() {
        return enable;
    }

    public boolean isStatisticsEnabled() {
        return statisticsEnabled;
    }

    public int getMaxCapacity() {
        return maxCapacity;
    }

    public int getExpireTime() {
        return expireTime;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public void setStatisticsEnabled(boolean statisticsEnabled) {
        this.statisticsEnabled = statisticsEnabled;
    }

    public void setMaxCapacity(int maxCapacity) {
        this.maxCapacity = maxCapacity;
    }

    public void setExpireTime(int expireTime) {
        this.expireTime = expireTime;
    }
}
