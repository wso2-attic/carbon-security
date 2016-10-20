package org.wso2.carbon.security.caas.userstore.filebased.connector;

import org.wso2.carbon.kernel.utils.StringUtils;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.userstore.filebased.Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

/**
 * FileBased implementation of the CredentialStoreConnector.
 */
public class FileBasedCredentialStoreConnector implements CredentialStoreConnector {

    private CredentialStoreConnectorConfig credentialStoreConnectorConfig;

    private BufferedReader bufferedReader;

    /**
     * Number of columns represented in the csv.
     */
    private int numberOfColumns = 7;

    @Override
    public void init(CredentialStoreConnectorConfig credentialStoreConnectorConfig) throws CredentialStoreException {
        this.credentialStoreConnectorConfig = credentialStoreConnectorConfig;

        String userStoreFile = credentialStoreConnectorConfig.getProperties().getProperty("storeFile");

        if (userStoreFile == null) {
            throw new CredentialStoreException("storeFile property is not provided for file based connector");
        }

        Path userStorePath = Paths.get(userStoreFile);

        try {
            bufferedReader = Files.newBufferedReader(userStorePath);
        } catch (IOException e) {
            throw new CredentialStoreException("Error initializing file based credential store connector", e);
        }
    }

    @Override
    public String getCredentialStoreId() {
        return null;
    }

    @Override
    public void authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {

        char [] password = null;
        String username = null;

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            } else if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getName();
            }
        }

        if (password == null || username == null) {
            throw new AuthenticationFailure("Information required for authentication not provided");
        }


        try {
            byte[] passwordBytes = String.valueOf(password).getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String passwordHash = new String(md.digest(passwordBytes), "UTF-8");

            bufferedReader.reset();
            String line;
            while (!StringUtils.isNullOrEmpty(line = bufferedReader.readLine())) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                String[] userData = line.split(Constants.DELIMITER);

                if (userData.length != numberOfColumns) {
                    throw new CredentialStoreException("Invalid user data found in FileBasedCredentialStoreConnector");
                }

                // Check if this is the same user
                if (userData[1].equals(username) && userData[2].equals(passwordHash)) {
                    return;
                }
            }

            throw new AuthenticationFailure("Failed to authenticate");
        } catch (IOException e) {
            throw new CredentialStoreException("An error occurred while authentication user", e);
        } catch (NoSuchAlgorithmException e) {
            // not returning e as it contains hash details
            throw new CredentialStoreException("An invalid Hash algorithm has been specified");
        }
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {
        boolean nameCallbackPresent = false;
        boolean passwordCallbackPresent = false;

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                nameCallbackPresent = true;
            }

            if (callback instanceof PasswordCallback) {
                passwordCallbackPresent = true;
            }
        }

        return nameCallbackPresent && passwordCallbackPresent;
    }

    @Override
    public CredentialStoreConnectorConfig getCredentialStoreConfig() {
        return credentialStoreConnectorConfig;
    }
}
