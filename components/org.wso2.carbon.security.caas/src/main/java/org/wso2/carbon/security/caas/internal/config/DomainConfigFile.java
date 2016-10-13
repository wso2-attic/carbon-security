package org.wso2.carbon.security.caas.internal.config;

import java.util.List;

/**
 * Domain config.
 */
public class DomainConfigFile {

    /**
     * List of domain configuration entries.
     */
    List<DomainConfigEntry> domainConfigEntries;

    /**
     * Get Domain configuration entries.
     *
     * @return List<DomainConfigEntry> - List of domain configuration entries
     */
    public List<DomainConfigEntry> getDomainConfigEntries() {
        return domainConfigEntries;
    }

    /**
     * Set Domain configuration entries.
     *
     * @param domains List<DomainConfigEntry> - List of domain configuration entries
     */
    public void setDomainConfigEntries(List<DomainConfigEntry> domains) {
        this.domainConfigEntries = domains;
    }
}
