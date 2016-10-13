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

import org.wso2.carbon.kernel.utils.StringUtils;

/**
 * Permission entry bean.
 *
 * @since 1.0.0
 */
public class PermissionEntry {

    /**
     * Type of the permission (resource type).
     */
    private String type;

    /**
     * Name of the resource associated with the permission.
     */
    private String name;

    /**
     * Associated action string for the permission.
     */
    private String actions;

    /**
     * Get permission type.
     *
     * @return String - permission type
     */
    public String getType() {

        return type;
    }

    /**
     * Set permission type.
     *
     * @param type String - permission type
     */
    public void setType(String type) {

        if (StringUtils.isNullOrEmpty(type)) {
            throw new IllegalArgumentException("Permission type cannot be null or empty.");

        }

        this.type = type;
    }

    /**
     * Get the associated resource name.
     *
     * @return String resource name
     */
    public String getName() {

        return name;
    }

    /**
     * Set the associated resource name.
     *
     * @param name resource name
     */
    public void setName(String name) {

        if (StringUtils.isNullOrEmpty(name)) {
            throw new IllegalArgumentException("Permission name cannot be null or empty.");
        }

        this.name = name;
    }

    /**
     * Get the associated actions for the permission.
     *
     * @return String actions related to the permission
     */
    public String getActions() {

        return actions;
    }

    /**
     * Set the associated actions for the permission.
     *
     * @param actions actions related to the permission
     */
    public void setActions(String actions) {

        if (StringUtils.isNullOrEmpty(actions)) {
            throw new IllegalArgumentException("Permission actions cannot be null or empty.");
        }

        this.actions = actions;
    }

}
