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

package org.wso2.carbon.security.caas.user.core.bean;

/**
 * Represents a resource.
 */
public class Resource {

    public static final String DELIMITER = ":";

    private String resourceDomain;
    private String resourceId;
    private String userId;
    private String identityStoreId;

    public Resource(String resourceDomain, String resourceId) {

        this.resourceDomain = resourceDomain;
        this.resourceId = resourceId;
    }

    public Resource(String resourceDomain, String resourceId, String userId, String identityStoreId) {

        this.resourceDomain = resourceDomain;
        this.resourceId = resourceId;
        this.userId = userId;
        this.identityStoreId = identityStoreId;
    }

    public static Resource getUniversalResource() {
        return new Resource("*", "*");
    }

    public String getResourceDomain() {
        return resourceDomain;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getResourceString() {
        return resourceDomain + DELIMITER + resourceId;
    }

    public User.UserBuilder getOwner() {
        return new User.UserBuilder()
                .setUserId(userId)
                .setIdentityStoreId(identityStoreId);
    }
}
