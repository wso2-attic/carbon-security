package org.wso2.carbon.security.caas.internal.config;

import java.util.Properties;

/**
 * Basic StoreConnector config.
 */
public class StoreConnectorConfig {

    private String storeConnectorId;

    private String storeConnectorType;

    private Properties properties;

    public StoreConnectorConfig(String storeConnectorId, String storeConnectorType, Properties properties) {
        this.storeConnectorId = storeConnectorId;
        this.storeConnectorType = storeConnectorType;
        this.properties = properties;
    }

    public String getStoreConnectorId() {
        return storeConnectorId;
    }

    public void setStoreConnectorId(String storeConnectorId) {
        this.storeConnectorId = storeConnectorId;
    }

    public String getStoreConnectorType() {
        return storeConnectorType;
    }

    public void setStoreConnectorType(String storeConnectorType) {
        this.storeConnectorType = storeConnectorType;
    }

    public Properties getProperties() {
        return properties;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }
}
