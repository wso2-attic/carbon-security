package org.wso2.carbon.security.caas.internal.config;

import org.wso2.carbon.security.caas.user.core.claim.MetaClaimMapping;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Domain configuration.
 */
public class DomainConfig {

    /**
     * List of domains.
     */
    List<String> domains = new ArrayList<>();

    /**
     * Domains to IdentityStoreConnector map.
     */
    Map<String, List<String>> domainIdentityStoreConnectors = new HashMap<>();

    /**
     * Domain to CredentialStoreConnector map.
     */
    Map<String, List<String>> domainCredentialStoreConnectors = new HashMap<>();

    /**
     * IdentityStoreConnector to MetaClaimMappings map.
     */
    Map<String, List<MetaClaimMapping>> identityStoreConnectorMapping = new HashMap<>();

    public DomainConfig(List<String> domains,
                        Map<String, List<String>> domainIdentityStoreConnectors,
                        Map<String, List<String>> domainCredentialStoreConnectors,
                        Map<String, List<MetaClaimMapping>> identityStoreConnectorMapping) {
        this.domains = domains;
        this.domainIdentityStoreConnectors = domainIdentityStoreConnectors;
        this.domainCredentialStoreConnectors = domainCredentialStoreConnectors;
        this.identityStoreConnectorMapping = identityStoreConnectorMapping;
    }

    public List<String> getDomains() {
        return domains;
    }

    public Map<String, List<String>> getDomainIdentityStoreConnectors() {
        return domainIdentityStoreConnectors;
    }

    public Map<String, List<String>> getDomainCredentialStoreConnectors() {
        return domainCredentialStoreConnectors;
    }

    public Map<String, List<MetaClaimMapping>> getIdentityStoreConnectorMapping() {
        return identityStoreConnectorMapping;
    }
}
