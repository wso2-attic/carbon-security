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

import org.wso2.carbon.security.caas.user.core.exception.StoreException;

/**
 * Represents a Role.
 */
public class Role {

    /**
     * Name of the role.
     */
    private String roleName;

    /**
     * Unique role id of the role.
     */
    private String roleId;

    /**
     * Authorisation connector id relevant to the role.
     */
    private String authorizationConnectorStoreId;

    private Role(String roleName, String roleId, String authorizationConnectorStoreId) {

        this.roleName = roleName;
        this.roleId = roleId;
        this.authorizationConnectorStoreId = authorizationConnectorStoreId;
    }

    /**
     * Get the name of this Role.
     *
     * @return Role name.
     */
    public String getName() {
        return roleName;
    }

    /**
     * Get the ID of the role.
     *
     * @return Id of the role.
     */
    public String getRoleId() {
        return roleId;
    }

    /**
     * Get the authorization store id.
     *
     * @return Id of the authorization store.
     */
    public String getAuthorizationStoreId() {
        return authorizationConnectorStoreId;
    }

    /**
     * Builder for role bean.
     */
    public static class RoleBuilder {

        private String roleName;
        private String roleId;
        private String authorizationStoreConnectorId;

        public RoleBuilder setRoleName(String roleName) {
            this.roleName = roleName;
            return this;
        }

        public RoleBuilder setRoleId(String roleId) {
            this.roleId = roleId;
            return this;
        }

        public RoleBuilder setAuthorizationStoreConnectorId(String authorizationStoreConnectorId) {
            this.authorizationStoreConnectorId = authorizationStoreConnectorId;
            return this;
        }

        public Role build() {

            if (roleName == null || roleId == null || authorizationStoreConnectorId == null) {
                throw new StoreException("Required data missing for building role.");
            }

            return new Role(roleName, roleId, authorizationStoreConnectorId);
        }
    }
}
