package org.wso2.carbon.security.caas.internal.config;

import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;

import java.util.List;

/**
 * Store connector configs.
 */
public class StoreConnectorsConfigEntry {

    List<IdentityStoreConnectorConfig> identityStoreConnectors;
    List<CredentialStoreConnectorConfig> credentialStoreConnectors;
    List<AuthorizationStoreConnectorConfig> authorizationStoreConnectors;

    public List<IdentityStoreConnectorConfig> getIdentityStoreConnectors() {
        return identityStoreConnectors;
    }

    public void setIdentityStoreConnectors(List<IdentityStoreConnectorConfig> identityStoreConnectors) {
        this.identityStoreConnectors = identityStoreConnectors;
    }

    public List<CredentialStoreConnectorConfig> getCredentialStoreConnectors() {
        return credentialStoreConnectors;
    }

    public void setCredentialStoreConnectors(List<CredentialStoreConnectorConfig> credentialStoreConnectors) {
        this.credentialStoreConnectors = credentialStoreConnectors;
    }

    public List<AuthorizationStoreConnectorConfig> getAuthorizationStoreConnectors() {
        return authorizationStoreConnectors;
    }

    public void setAuthorizationStoreConnectors(List<AuthorizationStoreConnectorConfig> authorizationStoreConnectors) {
        this.authorizationStoreConnectors = authorizationStoreConnectors;
    }
}
