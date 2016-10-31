package org.wso2.carbon.security.caas.user.core.config;

import java.util.Properties;

/**
 * * Config entry for CredentialStoreConnector..
 */
public class CredentialStoreConnectorConfig {

    private String connectorId;

    private String connectorType;

    private Properties properties;

    private String domainName;

    private String primaryAttribute;

    private int priority;

    public String getConnectorId() {
        return connectorId;
    }

    public Properties getProperties() {
        return properties;
    }

    public String getConnectorType() {
        return connectorType;
    }

    public void setConnectorId(String connectorId) {
        this.connectorId = connectorId;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }

    public void setConnectorType(String connectorType) {
        this.connectorType = connectorType;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public String getPrimaryAttribute() {
        return primaryAttribute;
    }

    public void setPrimaryAttribute(String primaryAttribute) {
        this.primaryAttribute = primaryAttribute;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }
}
