package org.wso2.carbon.security.usercore.exception;

/**
 * Created by jayanga on 3/10/16.
 */
public class CredentialStoreException extends Exception {

    public CredentialStoreException(String message) {
        super(message);
    }

    public CredentialStoreException(String message, Exception e) {
        super(message, e);
    }
}
