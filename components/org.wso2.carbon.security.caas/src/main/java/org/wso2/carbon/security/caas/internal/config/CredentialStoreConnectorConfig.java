package org.wso2.carbon.security.caas.internal.config;

/**
 * * Config entry for CredentialStoreConnector..
 */
public class CredentialStoreConnectorConfig extends StoreConnectorConfigEntry {

    private String domainName;

    private String primaryAttributeName;

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public String getPrimaryAttributeName() {
        return primaryAttributeName;
    }

    public void setPrimaryAttributeName(String primaryAttributeName) {
        this.primaryAttributeName = primaryAttributeName;
    }
}
