package org.wso2.carbon.security.caas.internal.config;

import java.util.List;

/**
 * Domain configuration entry.
 */
public class DomainConfigEntry {

    private String domainName;

    private List<DomainStoreConfigEntry> identityStoreConnectors;

    private List<DomainStoreConfigEntry> credentialStoreConnectors;

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public List<DomainStoreConfigEntry> getIdentityStoreConnectors() {
        return identityStoreConnectors;
    }

    public void setIdentityStoreConnectors(List<DomainStoreConfigEntry> identityStoreConnectors) {
        this.identityStoreConnectors = identityStoreConnectors;
    }

    public List<DomainStoreConfigEntry> getCredentialStoreConnectors() {
        return credentialStoreConnectors;
    }

    public void setCredentialStoreConnectors(List<DomainStoreConfigEntry> credentialStoreConnectors) {
        this.credentialStoreConnectors = credentialStoreConnectors;
    }
}
