package org.wso2.carbon.security.caas.userstore.filebased.connector;

import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;

/**
 * Factory for creating file based credential store connector..
 */
public class FileBasedCredentialStoreConnectorFactory implements CredentialStoreConnectorFactory {

    @Override
    public CredentialStoreConnector getInstance() {
        return new FileBasedCredentialStoreConnector();
    }
}
