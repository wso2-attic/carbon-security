package org.wso2.carbon.security.caas.internal.config.domain;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Domain configuration.
 */
public class DomainConfig {

    /**
     * Map between domain priority and domain names.
     */
    Map<String, Integer> domainNameToDomainPriorityMap = new HashMap<>();

    /**
     * Domains to IdentityStoreConnector map.
     */
    Map<String, List<DomainIdentityStoreConnectorConfigEntry>> domainIdentityStoreConnectors = new HashMap<>();

    public DomainConfig(Map<String, Integer> domainNameToDomainPriorityMap,
                        Map<String, List<DomainIdentityStoreConnectorConfigEntry>> domainIdentityStoreConnectors) {

        this.domainNameToDomainPriorityMap = domainNameToDomainPriorityMap;
        this.domainIdentityStoreConnectors = domainIdentityStoreConnectors;
    }

    public Map<String, Integer> getDomainNameToDomainPriorityMap() {
        return this.domainNameToDomainPriorityMap;
    }

    public Map<String, List<DomainIdentityStoreConnectorConfigEntry>> getDomainIdentityStoreConnectors() {
        return domainIdentityStoreConnectors;
    }
}
