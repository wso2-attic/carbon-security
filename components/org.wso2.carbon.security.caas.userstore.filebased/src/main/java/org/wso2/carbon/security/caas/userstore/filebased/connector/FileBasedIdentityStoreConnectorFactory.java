package org.wso2.carbon.security.caas.userstore.filebased.connector;

import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;

/**
 * Factory for creating file based identity store connector.
 */
public class FileBasedIdentityStoreConnectorFactory implements IdentityStoreConnectorFactory {

    @Override
    public IdentityStoreConnector getConnector() {
        return new FileBasedIdentityStoreConnector();
    }
}
