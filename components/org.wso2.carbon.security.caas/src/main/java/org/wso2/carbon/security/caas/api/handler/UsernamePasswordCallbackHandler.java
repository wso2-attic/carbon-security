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

package org.wso2.carbon.security.caas.api.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.security.caas.api.CarbonCallbackHandler;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
/**
 * <p>
 * This class extracts credentials from Basic Authorization header.
 * </p>
 *
 * @since 1.0.0
 */
public class UsernamePasswordCallbackHandler implements CarbonCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(UsernamePasswordCallbackHandler.class);

    private CarbonMessage carbonMessage;

    private String username;

    private char[] password;

    @Override
    public void setCarbonMessage(CarbonMessage carbonMessage) {
        this.carbonMessage = carbonMessage;
    }

    @Override
    public boolean canHandle() {

        if (carbonMessage == null || carbonMessage.getHeader("Authorization") == null) {
            return false;
        }

        String authorizationHeader = carbonMessage.getHeader("Authorization").trim();

        if (authorizationHeader.startsWith(CarbonSecurityConstants.HTTP_AUTHORIZATION_PREFIX_BASIC)) {

            String credentials = authorizationHeader.split("\\s+")[1];
            byte[] decodedByte = credentials.getBytes(StandardCharsets.UTF_8);
            String authDecoded = new String(Base64.getDecoder().decode(decodedByte), StandardCharsets.UTF_8);
            String[] authParts = authDecoded.split(":");
            if (authParts.length == 2) {
                username = authParts[0];
                password = authParts[1].toCharArray();

                if (log.isDebugEnabled()) {
                    log.debug("UsernamePasswordCallbackHandler will handle the request.");
                }
                return true;
            }
        }
        return false;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        if (callbacks != null) {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName(username);
                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(password);
                }
            }
            clearCredentials();
        }
    }

    private void clearCredentials() {
        username = null;
        if (password != null) {
            for (int i = 0; i < password.length; i++) {
                password[i] = ' ';
            }
            password = null;
        }
    }

}
