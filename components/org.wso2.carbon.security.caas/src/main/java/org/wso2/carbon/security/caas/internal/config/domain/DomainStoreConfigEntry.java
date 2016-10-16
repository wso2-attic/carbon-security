package org.wso2.carbon.security.caas.internal.config.domain;

import java.util.List;
import java.util.Map;

/**
 * Store connector config entry for domain config.
 */
public class DomainStoreConfigEntry {

    private String connectorName;

    /**
     * Domain IdentityStoreConnector attribute mapping configuration list.
     */
    private List<Map<String, String>> attributeMappings;

    public String getConnectorName() {
        return connectorName;
    }

    public void setConnectorName(String connectorName) {
        this.connectorName = connectorName;
    }

    public List<Map<String, String>> getAttributeMappings() {
        return attributeMappings;
    }

    public void setAttributeMappings(List<Map<String, String>> attributeMappings) {
        this.attributeMappings = attributeMappings;
    }
}
