package org.wso2.carbon.security.caas.user.core.config;

import java.util.List;
import java.util.Properties;

/**
 * Config entry for IdentityStoreConnector.
 */
public class IdentityStoreConnectorConfig {

    private String connectorId;
    private String connectorType;
    private Properties properties;
    private String domainName;
    private String primaryAttribute;
    private List<String> uniqueAttributes;
    private List<String> otherAttributes;

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

    public List<String> getUniqueAttributes() {
        return uniqueAttributes;
    }

    public void setUniqueAttributes(List<String> uniqueAttributes) {
        this.uniqueAttributes = uniqueAttributes;
    }

    public List<String> getOtherAttributes() {
        return otherAttributes;
    }

    public void setOtherAttributes(List<String> otherAttributes) {
        this.otherAttributes = otherAttributes;
    }
}
