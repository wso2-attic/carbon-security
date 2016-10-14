package org.wso2.carbon.security.caas.internal.config.domain;

import java.util.List;
import java.util.Map;

/**
 * Store connector config entry for domain config.
 */
public class DomainStoreConfigEntry {

    private String connectorId;

    /**
     * Domain IdentityStoreConnector attribute mapping configuration list.
     */
    private List<Map<String, String>> attributeMappings;

    public String getConnectorId() {
        return connectorId;
    }

    public void setConnectorId(String connectorId) {
        this.connectorId = connectorId;
    }

    public List<Map<String, String>> getAttributeMappings() {
        return attributeMappings;
    }

    public void setAttributeMappings(List<Map<String, String>> attributeMappings) {
        this.attributeMappings = attributeMappings;
    }
}
