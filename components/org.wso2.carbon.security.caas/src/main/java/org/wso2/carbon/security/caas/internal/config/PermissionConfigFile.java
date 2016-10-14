/*
*  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.security.caas.internal.config;

import java.util.Collections;
import java.util.List;

/**
 * This class illustrates the 'permissions.yml' file.
 */
public class PermissionConfigFile {

    /**
     * List of permission entries.
     */
    private List<PermissionEntry> permissions;

    /**
     * Get the list of permission entries.
     *
     * @return List of permission entries
     */
    public List<PermissionEntry> getPermissions() {

        if (permissions == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(permissions);
    }

    /**
     * Set a list of permission entries.
     *
     * @param permissions List<PermissionEntry> permissions
     */
    public void setPermissions(List<PermissionEntry> permissions) {

        this.permissions = permissions;
    }
}
