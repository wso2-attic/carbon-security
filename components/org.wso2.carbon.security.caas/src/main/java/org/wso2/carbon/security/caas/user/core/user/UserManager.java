package org.wso2.carbon.security.caas.user.core.user;

import org.wso2.carbon.security.caas.user.core.exception.UserManagerException;

/**
 * UserManager interface.
 *
 * The implementation of this interface is responsible for handling the globally unique user Id.
 *
 */
public interface UserManager {

    /**
     * Get global unique Id for a connector specific user Id.
     *
     * @param connectorUserId The connector specific user Id
     * @param connectorId     The connector Id
     * @return Globally unique user Id
     * @throws UserManagerException
     */
    String getUniqueUserId(String connectorUserId, String connectorId) throws UserManagerException;

    /**
     * Get connector specific user Id.
     *
     * @param uniqueUserId The globally unique user Id
     * @param connectorId  The connector Id
     * @return Connector specific user Id
     * @throws UserManagerException
     */
    String getConnectorUserId(String uniqueUserId, String connectorId) throws UserManagerException;
}
