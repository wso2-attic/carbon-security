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

package org.wso2.carbon.security.caas.user.core.config;

import java.util.Properties;

/**
 * Credential store configurations.
 */
public class CredentialStoreConnectorConfig {

    String connectorType;

    private Properties storeProperties;

    public CredentialStoreConnectorConfig(String connectorType, Properties properties) {
        this.connectorType = connectorType;
        this.storeProperties = properties;
    }

    public Properties getStoreProperties() {
        return storeProperties;
    }

    public String getConnectorType() {
        return connectorType;
    }

    public void setConnectorType(String connectorType) {
        this.connectorType = connectorType;
    }

    public void setStoreProperties(Properties storeProperties) {
        this.storeProperties = storeProperties;
    }
}
