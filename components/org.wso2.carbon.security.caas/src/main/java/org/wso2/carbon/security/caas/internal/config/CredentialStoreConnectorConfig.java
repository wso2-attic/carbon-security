package org.wso2.carbon.security.caas.internal.config;

import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConnectorConfig;

/**
 * * Config entry for CredentialStoreConnector..
 */
public class CredentialStoreConnectorConfig extends AuthorizationStoreConnectorConfig {

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
