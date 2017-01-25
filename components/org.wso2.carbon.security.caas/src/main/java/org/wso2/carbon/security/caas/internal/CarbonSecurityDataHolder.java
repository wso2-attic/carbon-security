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

package org.wso2.carbon.security.caas.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.caching.CarbonCachingService;
import org.wso2.carbon.identity.mgt.AuthorizationService;
import org.wso2.carbon.identity.mgt.RealmService;

/**
 * Carbon security data holder.
 * @since 1.0.0
 */
public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();
    private AuthorizationService authorizationService;
    private CarbonCachingService carbonCachingService;
    private BundleContext bundleContext = null;
    private RealmService realmService;

    private CarbonSecurityDataHolder() {
    }

    /**
     * Get the instance of this class.
     * @return CarbonSecurityDataHolder.
     */
    public static CarbonSecurityDataHolder getInstance() {
        return instance;
    }

    void registerCacheService(CarbonCachingService carbonCachingService)  {
        this.carbonCachingService = carbonCachingService;
    }

    public CarbonCachingService getCarbonCachingService() {
        return carbonCachingService;
    }

    void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    public BundleContext getBundleContext() {

        if (this.bundleContext == null) {
            throw new IllegalStateException("BundleContext is null.");
        }
        return bundleContext;
    }

    void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    void setAuthorizationService(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    public AuthorizationService getAuthorizationService() {

        if (this.authorizationService == null) {
            throw new IllegalStateException("Carbon Authorization Service is null.");
        }
        return this.authorizationService;
    }
}
