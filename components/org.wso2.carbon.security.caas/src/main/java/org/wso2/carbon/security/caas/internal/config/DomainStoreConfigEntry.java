package org.wso2.carbon.security.caas.internal.config;

import java.util.List;

/**
 * Store connector config entry for domain config.
 */
public class DomainStoreConfigEntry {

    private String storeConnectorId;

    /**
     * Domain IdentityStoreConnector attribute mapping configuration list.
     */
    private List<DomainAttributeConfigEntry> attributeMappings;

    public String getStoreConnectorId() {
        return storeConnectorId;
    }

    public void setStoreConnectorId(String storeConnectorId) {
        this.storeConnectorId = storeConnectorId;
    }

    public List<DomainAttributeConfigEntry> getAttributeMappings() {
        return attributeMappings;
    }

    public void setAttributeMappings(List<DomainAttributeConfigEntry> attributeMappings) {
        this.attributeMappings = attributeMappings;
    }
}
