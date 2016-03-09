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

package org.wso2.carbon.security.usercore.bean;

/**
 * Permission bean.
 */
public class Permission {

    private String resourceId;
    private String action;

    public Permission(String resourceId, String action) {
        this.resourceId = resourceId;
        this.action = action;
    }

    /**
     * Get the permission String (Resource ID + Action).
     * @return Permission string.
     */
    public String getPermissionString() {
        return resourceId + action;
    }

    /**
     * Get the resource id.
     * @return Resource id.
     */
    public String getResourceId() {
        return resourceId;
    }

    /**
     * Get the action.
     * @return Action.
     */
    public String getAction() {
        return action;
    }

    @Override
    public boolean equals(Object permission) {
        return permission instanceof Permission && ((Permission) permission).getPermissionString()
                .equals(resourceId + action);
    }

    @Override
    public int hashCode() {
        return getPermissionString().hashCode();
    }
}
