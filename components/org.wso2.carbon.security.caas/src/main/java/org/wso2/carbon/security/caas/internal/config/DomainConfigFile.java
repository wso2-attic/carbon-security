package org.wso2.carbon.security.caas.internal.config;

import java.util.List;

/**
 * Domain config.
 */
public class DomainConfigFile {

    /**
     * List of domain configuration entries.
     */
    List<DomainConfigEntry> domains;

    public List<DomainConfigEntry> getDomains() {
        return domains;
    }

    public void setDomains(List<DomainConfigEntry> domains) {
        this.domains = domains;
    }
}
