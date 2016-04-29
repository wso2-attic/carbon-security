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

package org.wso2.carbon.security.user.core.bean;

import org.wso2.carbon.security.user.core.exception.StoreException;

/**
 * Permission bean.
 */
public class Permission {

    private String authorizationStoreId;
    private String permissionId;

    private String resourceId;
    private String action;

    public Permission(String resourceId, String action) {
        this.resourceId = resourceId;
        this.action = action;
    }

    private Permission(String resourceId, String action, String permissionId, String authorizationStoreId) {
        this.resourceId = resourceId;
        this.action = action;
        this.permissionId = permissionId;
        this.authorizationStoreId = authorizationStoreId;
    }

    /**
     * Get the unique id of this permission.
     * @return Permission id.
     */
    public String getPermissionId() {
        return permissionId;
    }

    /**
     * Get the authorization store id.
     * @return Authorization store id.
     */
    public String getAuthorizationStoreId() {
        return authorizationStoreId;
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

    /**
     *
     */
    public static class PermissionBuilder {

        private String resourceId;
        private String action;
        private String permissionId;
        private String authorizationStoreId;

        public PermissionBuilder(String resourceId, String action, String permissionId, String authorizationStoreId) {
            this.resourceId = resourceId;
            this.action = action;
            this.permissionId = permissionId;
            this.authorizationStoreId = authorizationStoreId;
        }

        public Permission build() {

            if (resourceId == null || action == null || permissionId == null || authorizationStoreId == null) {
                throw new StoreException("Required data missing for building permission.");
            }

            return new Permission(resourceId, action, permissionId, authorizationStoreId);
        }
    }
}
