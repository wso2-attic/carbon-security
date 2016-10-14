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
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.CacheConfig;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.ConfigurationFileReadException;
import org.wso2.carbon.security.caas.user.core.util.FileUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Configuration builder for stores.
 *
 * @since 1.0.0
 */
public class StoreConfigBuilder {

    private StoreConfigBuilder() {

    }

    /**
     * Read store-config.yml file
     *
     * @return StoreConfig file from store-config.yml
     * @throws ConfigurationFileReadException on error in reading file
     * @throws IOException                    on file not found
     */
    private static StoreConfigFile buildStoreConfig() throws ConfigurationFileReadException, IOException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.STORE_CONFIG_FILE);

        // store-config.yml is a mandatory configuration file.
        return FileUtil.readConfigFile(file, StoreConfigFile.class);
    }

    /**
     * Builder a config object based on the store-config.yml properties.
     *
     * @return StoreConfig
     * @throws ConfigurationFileReadException on error in reading file
     * @throws IOException                    on file not found
     */
    public static StoreConfig getStoreConfig() throws IOException, ConfigurationFileReadException {

        StoreConfig storeConfig = new StoreConfig();

        // TODO: Include external config entries
//        Map<String, AuthorizationStoreConnectorConfig> externalConfigEntries = getExternalConfigEntries();

        StoreConfigFile storeConfigFile = buildStoreConfig();

        // TODO: Store config - additional store parameters - re-walk caching implementation

        // Check if the global cache is enabled.
        boolean cacheEnabled = storeConfigFile.isEnableCache();
        storeConfig.setEnableCache(cacheEnabled);

        // Load cache entries for credential store if the global cache is enabled.
        Map<String, CacheConfig> credentialStoreCacheConfigMap =
                getCacheEntriesForCredentialStore(storeConfigFile, cacheEnabled);

        storeConfig.setCredentialStoreCacheConfigMap(credentialStoreCacheConfigMap);

        // Load cache entries for identity store if the global cache is enabled.
        Map<String, CacheConfig> identityStoreCacheConfigMap =
                getCacheEntriesForIdentityStore(storeConfigFile, cacheEnabled);
        storeConfig.setIdentityStoreCacheConfigMap(identityStoreCacheConfigMap);

        // Load cache entries for authorization store if the global cache is enabled.
        Map<String, CacheConfig> authorizationStoreCacheConfigMap =
                getCacheEntriesForAuthorizationStore(storeConfigFile, cacheEnabled);
        storeConfig.setAuthorizationStoreCacheConfigMap(authorizationStoreCacheConfigMap);

        // Populate IdentityStoreConnectors
        Map<String, IdentityStoreConnectorConfig> identityStoreConnectorConfigMap =
                storeConfigFile.getStoreConnectors().getIdentityStoreConnectors()
                        .stream()
                        .collect(Collectors.toMap(IdentityStoreConnectorConfig::getConnectorId,
                                identityStoreConnectorConfig -> identityStoreConnectorConfig));

        storeConfig.setIdentityConnectorConfigMap(identityStoreConnectorConfigMap);

        // Populate CredentialStoreConnectors
        Map<String, CredentialStoreConnectorConfig> credentialStoreConnectorConfigMap =
                storeConfigFile.getStoreConnectors().getCredentialStoreConnectors()
                        .stream()
                        .collect(Collectors.toMap(CredentialStoreConnectorConfig::getConnectorId,
                                credentialStoreConnectorConfig -> credentialStoreConnectorConfig));

        storeConfig.setCredentialConnectorConfigMap(credentialStoreConnectorConfigMap);

        // Populate AuthorizationStoreConnectors
        Map<String, AuthorizationStoreConnectorConfig> authorizationStoreConnectorConfigMap =
                storeConfigFile.getStoreConnectors().getAuthorizationStoreConnectors()
                        .stream()
                        .collect(Collectors.toMap(AuthorizationStoreConnectorConfig::getConnectorId,
                                authorizationStoreConnectorConfig -> authorizationStoreConnectorConfig));

        storeConfig.setAuthorizationConnectorConfigMap(authorizationStoreConnectorConfigMap);

        return storeConfig;
    }

    /**
     * Read the config entries from external connector.yml files.
     * @return Map of Store config entries.
     */
//    private static Map<String, AuthorizationStoreConnectorConfig> getExternalConfigEntries() {
//
//        Map<String, AuthorizationStoreConnectorConfig> configEntryMap = new HashMap<>();
//        Path path = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security");
//
//        if (Files.exists(path)) {
//            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path, "*-connector.yml")) {
//                for (Path filePath : stream) {
//                    AuthorizationStoreConnectorConfig config =
//                            new Yaml().loadAs(Files.newInputStream(filePath),
//                                    AuthorizationStoreConnectorConfig.class);
//
//                    String name = config != null && !StringUtils.isNullOrEmpty(config.getConnectorId()) ?
//                                  config.getConnectorId().trim() : null;
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
     *
     * @param cacheEntries   Cache entry of the connector.
     * @param isCacheEnabled Is caching enabled in stores.
     * @return Map of CacheConfigs mapped to cache config name.
     */
    private static Map<String, CacheConfig> getCacheConfigs(List<CacheEntry> cacheEntries,
                                                            boolean isCacheEnabled) {

        if (!isCacheEnabled || cacheEntries == null) {
            return Collections.emptyMap();
        }

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

    /**
     * Get cache entries for authorization store if the global cache is enabled.
     *
     * @param storeConfigFile Store config file data.
     * @param isCacheEnabled  Is caching enabled in stores.
     * @return map of authorization store id and cache config
     */
    private static Map<String, CacheConfig> getCacheEntriesForAuthorizationStore(StoreConfigFile storeConfigFile,
                                                                                 boolean isCacheEnabled) {

        StoreConfigEntry storeConfigEntry = storeConfigFile.getCredentialStore();
        List<CacheEntry> authorizationStoreCacheEntries = storeConfigEntry != null
                ? storeConfigEntry.getCaches()
                : new ArrayList<>();

        return getCacheConfigs(authorizationStoreCacheEntries, isCacheEnabled);
    }

    /**
     * Get cache entries for identity store if the global cache is enabled.
     *
     * @param storeConfigFile Store config file data.
     * @param isCacheEnabled  Is caching enabled in stores.
     * @return map of identity store id and cache config
     */
    private static Map<String, CacheConfig> getCacheEntriesForIdentityStore(StoreConfigFile storeConfigFile,
                                                                            boolean isCacheEnabled) {

        StoreConfigEntry storeConfigEntry = storeConfigFile.getCredentialStore();
        List<CacheEntry> identityStoreCacheEntries = storeConfigEntry != null
                ? storeConfigEntry.getCaches()
                : new ArrayList<>();

        return getCacheConfigs(identityStoreCacheEntries, isCacheEnabled);
    }

    /**
     * Get cache entries for credential store if the global cache is enabled.
     *
     * @param storeConfigFile Store config file data.
     * @param isCacheEnabled  Is caching enabled in stores.
     * @return map of credential store id and cache config
     */
    private static Map<String, CacheConfig> getCacheEntriesForCredentialStore(StoreConfigFile storeConfigFile,
                                                                              boolean isCacheEnabled) {

        StoreConfigEntry storeConfigEntry = storeConfigFile.getCredentialStore();
        List<CacheEntry> credentialStoreCacheEntries = storeConfigEntry != null
                ? storeConfigEntry.getCaches()
                : new ArrayList<>();

        return getCacheConfigs(credentialStoreCacheEntries, isCacheEnabled);
    }
}
