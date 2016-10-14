package org.wso2.carbon.security.caas.internal.config.domain;

/**
 * Domain attribute mapping config entry.
 */
public class DomainAttributeConfigEntry {

    private String claimURI;

    private String attribute;

    public String getAttribute() {
        return attribute;
    }

    public void setAttribute(String attribute) {
        this.attribute = attribute;
    }

    public String getClaimURI() {
        return claimURI;
    }

    public void setClaimURI(String claimURI) {
        this.claimURI = claimURI;
    }
}
