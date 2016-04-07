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

package org.wso2.carbon.security.internal.config;

import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;
import org.wso2.carbon.security.usercore.config.CredentialStoreConfig;
import org.wso2.carbon.security.usercore.config.IdentityStoreConfig;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

/**
 * Configuration builder for stores.
 */
public class StoreConfigBuilder {




    /**
     * Build a IdentityStoreConfig from a file.
     * @param fileName Name of the configuration file.
     * @return Instance of IdentityStoreConfig.
     */
    public static IdentityStoreConfig buildIdentityStoreConfig(String fileName) throws IOException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                              fileName);

        Yaml yaml = new Yaml();
        Map<String, String> values = (Map<String, String>) yaml.load(Files.newInputStream(file));

        Properties storeProperties = new Properties();
        values.forEach(storeProperties::put);

        return new IdentityStoreConfig(storeProperties);
    }

    /**
     * Build a CredentialStoreConfig from a file.
     * @param fileName Name of the configuration file.
     * @return Instance of CredentialStoreConfig.
     */
    public static CredentialStoreConfig buildCredentialStoreConfig(String fileName) throws IOException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                              fileName);

        Yaml yaml = new Yaml();
        Map<String, String> values = (Map<String, String>) yaml.load(Files.newInputStream(file));

        Properties storeProperties = new Properties();
        values.forEach(storeProperties::put);

        return new CredentialStoreConfig(storeProperties);
    }
}
