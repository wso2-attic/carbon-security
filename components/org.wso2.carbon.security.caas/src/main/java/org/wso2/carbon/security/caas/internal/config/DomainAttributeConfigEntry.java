package org.wso2.carbon.security.caas.internal.config;

/**
 * Domain attribute mapping config entry.
 */
public class DomainAttributeConfigEntry {

    private String attribute;

    private String claimURI;

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
