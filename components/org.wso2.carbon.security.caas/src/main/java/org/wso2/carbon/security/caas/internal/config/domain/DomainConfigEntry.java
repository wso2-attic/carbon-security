package org.wso2.carbon.security.caas.internal.config.domain;

import java.util.List;

/**
 * Domain configuration entry.
 */
public class DomainConfigEntry {

    /**
     * Unique name of the domain.
     */
    private String domain;

    /**
     * Priority level of the domain
     */
    private int priority;

    /**
     * IdentityStoreConnector domain configuration list.
     */
    private List<DomainStoreConfigEntry> identityStoreConnectors;

    /**
     * Get the name of the domain.
     *
     * @return Name of the domain
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Set the name of the domain.
     *
     * @param domain Name of the domain
     */
    public void setDomain(String domain) {
        this.domain = domain;
    }

    /**
     * Get the priority level of the domain.
     *
     * @return integer - domain priority level
     */
    public int getDomainPriority() {
        return priority;
    }

    /**
     * Set the priority level of the domain.
     *
     * @param priority - integer domain level priority
     */
    public void setPriority(int priority) {
        this.priority = priority;
    }

    /**
     * Get a list of domain store configuration entries for identity connectors.
     *
     * @return DomainStoreConfigEntry
     */
    public List<DomainStoreConfigEntry> getIdentityStoreConnectors() {
        return identityStoreConnectors;
    }

    /**
     * Set a list of domain store configuration entries for identity connectors.
     *
     * @param identityStoreConnectors List<DomainStoreConfigEntry>
     */
    public void setIdentityStoreConnectors(List<DomainStoreConfigEntry> identityStoreConnectors) {
        this.identityStoreConnectors = identityStoreConnectors;
    }
}
