package org.wso2.carbon.security.caas.userstore.filebased.connector;

import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;

/**
 * Factory for creating file based authorization store connector.
 */
public class FileBasedAuthorizationStoreConnectorFactory implements AuthorizationStoreConnectorFactory {

    @Override
    public AuthorizationStoreConnector getInstance() {
        return new FileBasedAuthorizationStoreConnector();
    }
}
