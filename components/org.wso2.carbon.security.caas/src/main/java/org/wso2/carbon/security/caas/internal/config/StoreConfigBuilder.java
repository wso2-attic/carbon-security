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
import org.wso2.carbon.security.caas.user.core.exception.CarbonSecurityConfigException;
import org.wso2.carbon.security.caas.user.core.util.FileUtil;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
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
     * @throws CarbonSecurityConfigException on error in reading file
     */
    private static StoreConfigFile buildStoreConfig() throws CarbonSecurityConfigException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.STORE_CONFIG_FILE);

        // store-config.yml is a mandatory configuration file.
        return FileUtil.readConfigFile(file, StoreConfigFile.class);
    }

    /**
     * Builder a config object based on the store-config.yml properties.
     *
     * @return StoreConfig
     * @throws CarbonSecurityConfigException
     */
    public static StoreConfig getStoreConfig() throws CarbonSecurityConfigException {

        StoreConfig storeConfig = new StoreConfig();

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

        // Load external connector config files
        StoreConnectorsConfigEntry storeConnectors = storeConfigFile.getStoreConnectors();

        List<IdentityStoreConnectorConfig> identityStoreConnectorConfigs =
                storeConnectors.getIdentityStoreConnectors();

        identityStoreConnectorConfigs.addAll(getExternalIdentityStoreConnectorConfig());

        List<CredentialStoreConnectorConfig> credentialStoreConnectorConfigs =
                storeConnectors.getCredentialStoreConnectors();

        credentialStoreConnectorConfigs.addAll(getExternalCredentialStoreConnectorConfig());

        List<AuthorizationStoreConnectorConfig> authorizationStoreConnectorConfigs =
                storeConnectors.getAuthorizationStoreConnectors();

        authorizationStoreConnectorConfigs.addAll(getExternalAuthorizationStoreConnectorConfig());


        // Populate IdentityStoreConnectors
        Map<String, IdentityStoreConnectorConfig> identityStoreConnectorConfigMap =
                storeConfigFile.getStoreConnectors().getIdentityStoreConnectors().stream().collect(
                Collectors.toMap(IdentityStoreConnectorConfig::getConnectorId,
                        identityStoreConnectorConfig -> identityStoreConnectorConfig)
        );

        storeConfig.setIdentityConnectorConfigMap(identityStoreConnectorConfigMap);

        // Populate CredentialStoreConnectors
        Map<String, CredentialStoreConnectorConfig> credentialStoreConnectorConfigMap =
                credentialStoreConnectorConfigs.stream().collect(
                Collectors.toMap(CredentialStoreConnectorConfig::getConnectorId,
                        credentialStoreConnectorConfig -> credentialStoreConnectorConfig)
        );

        storeConfig.setCredentialConnectorConfigMap(credentialStoreConnectorConfigMap);

        // Populate AuthorizationStoreConnectors
        Map<String, AuthorizationStoreConnectorConfig> authorizationStoreConnectorConfigMap =
                authorizationStoreConnectorConfigs.stream().collect(
                Collectors.toMap(AuthorizationStoreConnectorConfig::getConnectorId,
                        authorizationStoreConnectorConfig -> authorizationStoreConnectorConfig)
        );

        storeConfig.setAuthorizationConnectorConfigMap(authorizationStoreConnectorConfigMap);

        return storeConfig;
    }

    /**
     * Read the IdentityStoreConnector config entries from external identity-connector.yml files.
     *
     * @return List of external IdentityStoreConnector config entries.
     * @throws CarbonSecurityConfigException
     */
    private static List<IdentityStoreConnectorConfig> getExternalIdentityStoreConnectorConfig()
            throws CarbonSecurityConfigException {

        List<IdentityStoreConnectorConfig> configEntries = new ArrayList<>();
        Path path = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security");

        if (Files.exists(path)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path, "*-identity-connector.yml")) {
                for (Path filePath : stream) {
                    IdentityStoreConnectorConfig config = new Yaml().loadAs(Files.newInputStream(filePath),
                            IdentityStoreConnectorConfig.class);

                    configEntries.add(config);
                }
            } catch (DirectoryIteratorException | IOException e) {
                throw new CarbonSecurityConfigException("Failed to read identity connector files from path: "
                        + path.toString(), e);
            }
        }

        return configEntries;
    }
    /**
     * Read the CredentialStoreConnector config entries from external identity-connector.yml files.
     *
     * @return List of external CredentialStoreConnector Store config entries.
     * @throws CarbonSecurityConfigException
     */
    private static List<CredentialStoreConnectorConfig> getExternalCredentialStoreConnectorConfig()
            throws CarbonSecurityConfigException {

        List<CredentialStoreConnectorConfig> configEntries = new ArrayList<>();
        Path path = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security");

        if (Files.exists(path)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path, "*-credential-connector.yml")) {
                for (Path filePath : stream) {
                    CredentialStoreConnectorConfig config = new Yaml().loadAs(Files.newInputStream(filePath),
                            CredentialStoreConnectorConfig.class);

                    configEntries.add(config);
                }
            } catch (DirectoryIteratorException | IOException e) {
                throw new CarbonSecurityConfigException("Failed to read credential store connector files from path: "
                        + path.toString(), e);
            }
        }

        return configEntries;
    }

    /**
     * Read the AuthorizationStoreConnector config entries from external identity-connector.yml files.
     *
     * @return List of Store external AuthorizationStoreConnector config entries.
     * @throws CarbonSecurityConfigException
     */
    private static List<AuthorizationStoreConnectorConfig> getExternalAuthorizationStoreConnectorConfig()
            throws CarbonSecurityConfigException {

        List<AuthorizationStoreConnectorConfig> configEntries = new ArrayList<>();
        Path path = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security");

        if (Files.exists(path)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path, "*-authorization-connector.yml")) {
                for (Path filePath : stream) {
                    AuthorizationStoreConnectorConfig config = new Yaml().loadAs(Files.newInputStream(filePath),
                            AuthorizationStoreConnectorConfig.class);

                    configEntries.add(config);
                }
            } catch (DirectoryIteratorException | IOException e) {
                throw new CarbonSecurityConfigException("Failed to read authorization store connector files from path: "
                        + path.toString(), e);
            }
        }

        return configEntries;
    }

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
