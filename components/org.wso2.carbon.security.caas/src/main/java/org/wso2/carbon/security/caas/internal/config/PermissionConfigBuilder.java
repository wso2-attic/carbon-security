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

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.exception.PermissionConfigException;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Builds PermissionConfigFile from the permissions.yml.
 *
 * @since 1.0.0
 */
public class PermissionConfigBuilder {

    private PermissionConfigBuilder() {
    }

    /**
     * Parses &amp; creates the object model for the PermissionConfigFile from the permissions.yml.
     *
     * @return PermissionConfigFile
     */
    public static PermissionConfigFile buildPermissionConfig()
            throws PermissionConfigException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.PERMISSION_CONFIG_FILE);

        if (Files.exists(file)) {
            try (Reader in = new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8)) {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                return yaml.loadAs(in, PermissionConfigFile.class);
            } catch (IOException e) {
                throw new PermissionConfigException(String
                        .format("Error loading %s permission configuration file",
                                CarbonSecurityConstants.PERMISSION_CONFIG_FILE), e);
            }
        }

        throw new PermissionConfigException(String
                .format("Permission configuration file %s not found",
                        CarbonSecurityConstants.PERMISSION_CONFIG_FILE));
    }

}
