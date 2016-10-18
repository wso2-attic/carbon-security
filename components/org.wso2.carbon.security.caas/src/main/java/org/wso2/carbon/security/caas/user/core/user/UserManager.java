package org.wso2.carbon.security.caas.user.core.user;

import org.wso2.carbon.security.caas.user.core.exception.UserManagerException;

/**
 * UserManager interface.
 */
public interface UserManager {

    public String getUniqueUserId(String connectorUserId, String connectorId) throws UserManagerException;

    public String getConnectorUserId(String uniqueUserId, String connectorId) throws UserManagerException;
}
