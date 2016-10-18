package org.wso2.carbon.security.caas.internal.config;

/**
 * CredentialStoreConnector configuration entry in store-config.
 */
public class CredentialStoreConnectorConfigEntry extends StoreConnectorConfigEntry {

    String domainName;

    String primaryAttribute;

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public String getPrimaryAttribute() {
        return primaryAttribute;
    }

    public void setPrimaryAttribute(String primaryAttribute) {
        this.primaryAttribute = primaryAttribute;
    }
}
