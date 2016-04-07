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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;
import org.wso2.carbon.security.usercore.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.usercore.config.CredentialStoreConfig;
import org.wso2.carbon.security.usercore.config.IdentityStoreConfig;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Configuration builder for stores.
 */
public class StoreConfigBuilder {

    private static final Logger log = LoggerFactory.getLogger(StoreConfigBuilder.class);

    public static void buildStoreConfig() {

        Map<String, Properties> connectors = getAllConnectors();
        Map<String, Properties> localConnectors = new HashMap<>();

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                              "store-config.yml");
        if (Files.exists(file)) {
            try (Reader in = new InputStreamReader(Files.newInputStream(file), StandardCharsets.ISO_8859_1)) {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                Map<String, ?> values = (Map<String, ?>) new Yaml().load(in);
                if(values == null) {
                    throw new IllegalArgumentException("Unable to read ");
                }

                if(values.get(CarbonSecurityConstants.STORE_CONNECTORS) != null) {
                    ((List<Map<String, String>>)values.get(CarbonSecurityConstants.STORE_CONNECTORS)).forEach(
                            localConnector -> {
                                String connectorName = localConnector.get("name");
                                if (connectorName == null && connectorName.trim().isEmpty()) {
                                    throw new IllegalArgumentException("Unable to find the 'name' entry in the file "
                                                                       + localConnector
                                            .toString());
                                }
                                localConnector.remove("name");
                                Properties storeProperties = new Properties();
                                localConnector.forEach(storeProperties::put);
                                localConnectors.put(connectorName, storeProperties);
                            }
                    );
                }

                if(values.get(CarbonSecurityConstants.CREDENTIAL_STORE) != null) {
                    Map<String, Properties> credentialConnectorMap = getStoreConfig((Map<String,
                            String>) values.get(CarbonSecurityConstants.CREDENTIAL_STORE), connectors, localConnectors);
                    if(credentialConnectorMap.size() > 0) {
                        credentialConnectorMap.entrySet().forEach(
                                entry -> CarbonSecurityDataHolder.getInstance().addCredentialStoreConfig(entry.getKey
                                        (), new CredentialStoreConfig(entry.getValue()))
                        );
                    }
                } else {
                    log.warn("TODO");
                }

                if(values.get(CarbonSecurityConstants.IDENTITY_STORE) != null) {
                    Map<String, Properties> identityStoreConnectorMap = getStoreConfig((Map<String,
                            String>) values.get(CarbonSecurityConstants.IDENTITY_STORE), connectors, localConnectors);
                    if(identityStoreConnectorMap.size() > 0) {
                        identityStoreConnectorMap.entrySet().forEach(
                                entry -> CarbonSecurityDataHolder.getInstance().addIdentityStoreConfig(entry.getKey
                                        (), new IdentityStoreConfig(entry.getValue()))
                        );
                    }
                } else {
                    log.warn("TODO");
                }

                if(values.get(CarbonSecurityConstants.AUTHORIZATION_STORE) != null) {
                    Map<String, Properties> credentialConnectorMap = getStoreConfig((Map<String,
                            String>) values.get(CarbonSecurityConstants.AUTHORIZATION_STORE), connectors, localConnectors);
                    if(credentialConnectorMap.size() > 0) {
                        credentialConnectorMap.entrySet().forEach(
                                entry -> CarbonSecurityDataHolder.getInstance().addAuthorizationStoreConfig(entry.getKey
                                        (), new AuthorizationStoreConfig(entry.getValue()))
                        );
                    }
                } else {
                    log.warn("TODO");
                }

            } catch (IOException e) {
                String msg = "Error while loading store-config.yml configuration file";
                throw new RuntimeException(msg, e);
            }
        }
    }

    private static  Map<String, Properties> getStoreConfig(Map<String, String> connectorProperties, Map<String,
            Properties> connectors, Map<String, Properties> localConnectors) {

        Map<String, Properties> connectorConfigMap = new HashMap<>();
        String connectorName = connectorProperties.get("connector");

        if(connectorName != null) {
            connectorProperties.remove("connector");
            Arrays.asList(connectorName.split(",")).forEach(
                    connector -> {
                        if(connector.startsWith("#")) {
                            Properties properties = localConnectors.get(connector.substring(1));
                            Properties updatedProperties = new Properties();
                            properties.forEach(updatedProperties::put);
                            if(connectorProperties.size() > 0) {
                                connectorProperties.forEach(updatedProperties::put);
                            }

                            connectorConfigMap.put(connector.substring(1), updatedProperties);
                        } else {
                            Properties properties = connectors.get(connector);
                            Properties updatedProperties = new Properties();
                            properties.forEach(updatedProperties::put);
                            if(connectorProperties.size() > 0) {
                                connectorProperties.forEach(updatedProperties::put);
                            }

                            connectorConfigMap.put(connector, updatedProperties);
                        }
                    }
            );
        } else {
            //TODO
        }

        return connectorConfigMap;
    }

    private static Map<String, Properties> getAllConnectors() {

        Map<String, Properties> connectorProperties = new HashMap<>();

        Path path = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security");

        if (Files.exists(path)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path, "*-connector.yml")) {
                for (Path entry : stream) {
                    Map<String, String> values = (Map<String, String>) new Yaml().load(Files.newInputStream(entry));

                    String connectorName = values.get("name");
                    if (connectorName == null && connectorName.trim().isEmpty()) {
                        throw new IllegalArgumentException("Unable to find the 'name' entry in the file " + entry
                                .toString());
                    }
                    values.remove("name");
                    Properties storeProperties = new Properties();
                    values.forEach(storeProperties::put);
                    connectorProperties.put(connectorName, storeProperties);
                }
            } catch (DirectoryIteratorException | IOException ex) {
                // TODO
            }
        }

        return connectorProperties;
    }


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
