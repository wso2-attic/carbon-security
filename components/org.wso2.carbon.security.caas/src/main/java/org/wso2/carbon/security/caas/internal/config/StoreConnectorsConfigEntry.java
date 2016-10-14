package org.wso2.carbon.security.caas.internal.config;

import java.util.List;

/**
 * Store connector configs.
 */
public class StoreConnectorsConfigEntry {

    List<IdentityStoreConnectorConfigEntry> identityStoreConnectors;
    List<CredentialStoreConnectorConfigEntry> credentialStoreConnectors;
    List<StoreConnectorConfigEntry> authorizationStoreConnectors;

    public List<IdentityStoreConnectorConfigEntry> getIdentityStoreConnectors() {
        return identityStoreConnectors;
    }

    public void setIdentityStoreConnectors(List<IdentityStoreConnectorConfigEntry> identityStoreConnectors) {
        this.identityStoreConnectors = identityStoreConnectors;
    }

    public List<CredentialStoreConnectorConfigEntry> getCredentialStoreConnectors() {
        return credentialStoreConnectors;
    }

    public void setCredentialStoreConnectors(List<CredentialStoreConnectorConfigEntry> credentialStoreConnectors) {
        this.credentialStoreConnectors = credentialStoreConnectors;
    }

    public List<StoreConnectorConfigEntry> getAuthorizationStoreConnectors() {
        return authorizationStoreConnectors;
    }

    public void setAuthorizationStoreConnectors(List<StoreConnectorConfigEntry> authorizationStoreConnectors) {
        this.authorizationStoreConnectors = authorizationStoreConnectors;
    }
}
