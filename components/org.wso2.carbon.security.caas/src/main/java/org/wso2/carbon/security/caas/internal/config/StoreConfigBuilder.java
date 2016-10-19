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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.config.CacheConfig;
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Configuration builder for stores.
 * @since 1.0.0
 */
public class StoreConfigBuilder {

    private static final Logger log = LoggerFactory.getLogger(StoreConfigBuilder.class);

    private static StoreConfigFile buildStoreConfig() {
        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.STORE_CONFIG_FILE);

        // store-config.yml is a mandatory configuration file.
        if (Files.exists(file)) {
            try (Reader in = new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8)) {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                return yaml.loadAs(in, StoreConfigFile.class);
            } catch (IOException e) {
                throw new RuntimeException("Error while loading " + CarbonSecurityConstants.STORE_CONFIG_FILE + " " +
                        "configuration file.", e);
            }
        } else {
            throw new RuntimeException("Configuration file " + CarbonSecurityConstants.STORE_CONFIG_FILE + "' is not " +
                    "available.");
        }
    }

    /**
     * Builder a config object based on the store-config.yml properties.
     * @return StoreConfig
     */
    public static StoreConfig getStoreConfig() {

        StoreConfig storeConfig = new StoreConfig();

        // TODO: Include external config entries
//        Map<String, StoreConnectorConfigEntry> externalConfigEntries = getExternalConfigEntries();

        StoreConfigFile storeConfigFile = buildStoreConfig();

        // Validate for all mandatory parts in the store config file.
        if (storeConfigFile == null || storeConfigFile.getCredentialStore() == null
            || storeConfigFile.getAuthorizationStore() == null || storeConfigFile.getIdentityStore() == null) {
            throw new IllegalArgumentException("Invalid or missing configurations in the file - " +
                                               CarbonSecurityConstants.STORE_CONFIG_FILE);
        }

        // Check if the global cache is enabled.
        boolean cacheEnabled = storeConfigFile.isEnableCache();
        storeConfig.setEnableCache(cacheEnabled);

        // Load cache entries for credential store if the global cache is enabled.
        List<CacheEntry> credentialStoreCacheEntries = storeConfigFile.getCredentialStore().getCaches();
        Map<String, CacheConfig> credentialStoreCacheConfigMap;

        if (cacheEnabled && credentialStoreCacheEntries != null && !credentialStoreCacheEntries.isEmpty()) {
            credentialStoreCacheConfigMap = getCacheConfigs(credentialStoreCacheEntries);
        } else {
            credentialStoreCacheConfigMap = Collections.emptyMap();
        }

        storeConfig.setCredentialStoreCacheConfigMap(credentialStoreCacheConfigMap);

        // Load cache entries for identity store if the global cache is enabled.
        List<CacheEntry> identityStoreCacheEntries = storeConfigFile.getIdentityStore().getCaches();
        Map<String, CacheConfig> identityStoreCacheConfigMap;

        if (cacheEnabled && identityStoreCacheEntries != null && !identityStoreCacheEntries.isEmpty()) {
            identityStoreCacheConfigMap = getCacheConfigs(identityStoreCacheEntries);
        } else {
            identityStoreCacheConfigMap = Collections.emptyMap();
        }

        storeConfig.setIdentityStoreCacheConfigMap(identityStoreCacheConfigMap);

        // Load cache entries for authorization store if the global cache is enabled.
        List<CacheEntry> authorizationStoreCacheEntries = storeConfigFile.getAuthorizationStore().getCaches();
        Map<String, CacheConfig> authorizationStoreCacheConfigMap;

        if (cacheEnabled && authorizationStoreCacheEntries != null && !authorizationStoreCacheEntries.isEmpty()) {
            authorizationStoreCacheConfigMap = getCacheConfigs(authorizationStoreCacheEntries);
        } else {
            authorizationStoreCacheConfigMap = Collections.emptyMap();
        }
        storeConfig.setAuthorizationStoreCacheConfigMap(authorizationStoreCacheConfigMap);

        // TODO: Load connector configs
        storeConfig.setIdentityConnectorConfigMap(Collections.emptyMap());
        storeConfig.setCredentialConnectorConfigMap(Collections.emptyMap());
        storeConfig.setAuthorizationConnectorConfigMap(Collections.emptyMap());

        return storeConfig;
    }

    /**
     * Read the config entries from external connector.yml files.
     * @return Map of Store config entries.
     */
//    private static Map<String, StoreConnectorConfigEntry> getExternalConfigEntries() {
//
//        Map<String, StoreConnectorConfigEntry> configEntryMap = new HashMap<>();
//        Path path = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security");
//
//        if (Files.exists(path)) {
//            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path, "*-connector.yml")) {
//                for (Path filePath : stream) {
//                    StoreConnectorConfigEntry config = new Yaml().loadAs(Files.newInputStream(filePath),
//                                                                         StoreConnectorConfigEntry.class);
//
//                    String name = config != null && !StringUtils.isNullOrEmpty(config.getConnectorName()) ?
//                                  config.getConnectorName().trim() : null;
//                    if (name != null) {
//                        configEntryMap.put(name, config);
//                    } else {
//                        log.warn("Connector name is not available in the connector config file: "
//                                 + filePath.toString());
//                    }
//                }
//            } catch (DirectoryIteratorException | IOException ex) {
//                throw new RuntimeException("Failed to read connector files from path: " + path.toString(), ex);
//            }
//        }
//
//        return configEntryMap;
//    }

    /**
     * Get cache configs for each connector.
     * @param cacheEntries Cache entry of the connector.
     * @return Map of CacheConfigs.
     */
    private static Map<String, CacheConfig> getCacheConfigs(List<CacheEntry> cacheEntries) {

        return cacheEntries.stream()
                .filter(cacheEntry -> !(cacheEntry.getName() == null || cacheEntry.getName().isEmpty()))
                .map(cacheEntry -> {
                    if (cacheEntry.getCacheConfig() == null) {
                        cacheEntry.setCacheConfig(new CacheConfig());
                    }
                    return cacheEntry;
                })
                .collect(Collectors.toMap(CacheEntry::getName, CacheEntry::getCacheConfig));
    }
}
