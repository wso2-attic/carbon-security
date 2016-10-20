package org.wso2.carbon.security.caas.user.core.config;

import java.util.Properties;

/**
 * Basic StoreConnector config.
 */
public class AuthorizationStoreConnectorConfig {

    private String connectorId;

    private String connectorType;

    private Properties properties;

    public String getConnectorId() {
        return connectorId;
    }

    public void setConnectorId(String connectorId) {
        this.connectorId = connectorId;
    }

    public String getConnectorType() {
        return connectorType;
    }

    public void setConnectorType(String connectorType) {
        this.connectorType = connectorType;
    }

    public Properties getProperties() {
        return properties;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }
}
