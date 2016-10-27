/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.caas.userstore.filebased.connector;

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
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

/**
 * FileBased implementation of the CredentialStoreConnector.
 */
public class FileBasedCredentialStoreConnector implements CredentialStoreConnector {

    private CredentialStoreConnectorConfig credentialStoreConnectorConfig;

    private Path credentialStorePath;

    /**
     * Number of columns represented in the csv.
     */
    private int numberOfColumns = 2;

    @Override
    public void init(CredentialStoreConnectorConfig credentialStoreConnectorConfig) throws CredentialStoreException {
        this.credentialStoreConnectorConfig = credentialStoreConnectorConfig;

        String userStoreFile = credentialStoreConnectorConfig.getProperties().getProperty("storeFile");

        if (userStoreFile == null) {
            throw new CredentialStoreException("storeFile property is not provided for file based connector");
        }

        credentialStorePath = Paths.get(userStoreFile);
    }

    @Override
    public String getCredentialStoreId() {
        return null;
    }

    @Override
    public void authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {

        char[] password = null;
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

        String passwordString = new String(password);

        try (BufferedReader bufferedReader = Files.newBufferedReader(credentialStorePath)) {
            
            // TODO: HashPassword
//            byte[] passwordBytes = String.valueOf(password).getBytes("UTF-8");
//            MessageDigest md = MessageDigest.getInstance("SHA-256");
//            String passwordHash = new String(md.digest(passwordBytes), "UTF-8");

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                String[] userData = line.split(Constants.DELIMITER);

                if (userData.length != numberOfColumns) {
                    throw new CredentialStoreException("Invalid user data found in FileBasedCredentialStoreConnector");
                }

                // Check if this is the same user
                if (userData[0].equals(username) && userData[1].equals(passwordString)) {
                    return;
                }
            }

            throw new AuthenticationFailure("Failed to authenticate");
        } catch (IOException e) {
            throw new CredentialStoreException("An error occurred while authentication user", e);
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
