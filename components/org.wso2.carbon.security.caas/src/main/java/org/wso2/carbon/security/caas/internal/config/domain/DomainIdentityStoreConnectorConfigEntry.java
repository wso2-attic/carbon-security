package org.wso2.carbon.security.caas.internal.config.domain;

import java.util.Map;

/**
 * Domain IdentityStoreConnector configuration.
 */
public class DomainIdentityStoreConnectorConfigEntry {

    String identityStoreConnectorId;

    Map<String, String> attributeMappings;

    public DomainIdentityStoreConnectorConfigEntry(String identityStoreConnectorId, Map<String, String>
            attributeMappings) {
        this.identityStoreConnectorId = identityStoreConnectorId;
        this.attributeMappings = attributeMappings;
    }

    public String getIdentityStoreConnectorId() {
        return identityStoreConnectorId;
    }

    public void setIdentityStoreConnectorId(String identityStoreConnectorId) {
        this.identityStoreConnectorId = identityStoreConnectorId;
    }

    public Map<String, String> getAttributeMappings() {
        return attributeMappings;
    }

    public void setAttributeMappings(Map<String, String> attributeMappings) {
        this.attributeMappings = attributeMappings;
    }
}
