package org.wso2.carbon.security.caas.user.core.config;

import org.wso2.carbon.security.caas.internal.config.CredentialStoreConnectorConfig;

import java.util.List;

/**
 * Config entry for IdentityStoreConnector.
 */
public class IdentityStoreConnectorConfig extends CredentialStoreConnectorConfig {

    List<String> uniqueAttributes;

    List<String> otherAttributes;

    public List<String> getUniqueAttributes() {
        return uniqueAttributes;
    }

    public void setUniqueAttributes(List<String> uniqueAttributes) {
        this.uniqueAttributes = uniqueAttributes;
    }

    public List<String> getOtherAttributes() {
        return otherAttributes;
    }

    public void setOtherAttributes(List<String> otherAttributes) {
        this.otherAttributes = otherAttributes;
    }
}
