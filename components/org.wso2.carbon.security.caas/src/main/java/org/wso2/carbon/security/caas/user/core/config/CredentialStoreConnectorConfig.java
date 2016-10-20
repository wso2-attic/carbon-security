package org.wso2.carbon.security.caas.user.core.config;

/**
 * * Config entry for CredentialStoreConnector..
 */
public class CredentialStoreConnectorConfig extends AuthorizationStoreConnectorConfig {

    private String domainName;

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }
}
