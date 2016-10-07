package org.wso2.carbon.security.caas.internal.config;

import java.util.List;

/**
 * Domain configuration entry.
 */
public class DomainConfigEntry {

    /**
     * Unique name of the domain.
     */
    private String domainName;

    /**
     * Priority level of the domain
     */
    private int priority;

    /**
     * IdentityStoreConnector domain configuration list.
     */
    private List<DomainStoreConfigEntry> identityStoreConnectors;

    /**
     * CredentialStoreConnector domain configuration list.
     */
    private List<DomainStoreConfigEntry> credentialStoreConnectors;

    /**
     * Get the name of the domain.
     *
     * @return Name of the domain
     */
    public String getDomainName() {
        return domainName;
    }

    /**
     * Set the name of the domain.
     *
     * @param domainName Name of the domain
     */
    public void setDomainName(String domainName) {
        this.domainName = domainName;
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

    /**
     * Get a list of domain store configuration entries for credential connectors.
     *
     * @return DomainStoreConfigEntry
     */
    public List<DomainStoreConfigEntry> getCredentialStoreConnectors() {
        return credentialStoreConnectors;
    }

    /**
     * Set a list of domain store configuration entries for credential connectors.
     *
     * @param credentialStoreConnectors List<DomainStoreConfigEntry>
     */
    public void setCredentialStoreConnectors(List<DomainStoreConfigEntry> credentialStoreConnectors) {
        this.credentialStoreConnectors = credentialStoreConnectors;
    }
}
