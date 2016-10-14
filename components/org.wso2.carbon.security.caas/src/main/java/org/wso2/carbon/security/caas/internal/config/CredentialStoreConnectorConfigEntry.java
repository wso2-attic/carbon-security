package org.wso2.carbon.security.caas.internal.config;

/**
 * CredentialStoreConnector configuration entry in store-config.
 */
public class CredentialStoreConnectorConfigEntry extends StoreConnectorConfigEntry {

    String domain;

    String primaryAttribute;

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getPrimaryAttribute() {
        return primaryAttribute;
    }

    public void setPrimaryAttribute(String primaryAttribute) {
        this.primaryAttribute = primaryAttribute;
    }
}
