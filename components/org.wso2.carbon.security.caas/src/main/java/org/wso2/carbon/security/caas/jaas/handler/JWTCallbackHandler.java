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

package org.wso2.carbon.security.caas.jaas.handler;

import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.security.caas.jaas.CarbonCallback;
import org.wso2.carbon.security.caas.jaas.CarbonCallbackHandler;
import org.wso2.carbon.security.caas.jaas.util.CarbonSecurityConstants;

import java.io.IOException;
import java.text.ParseException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * <p>
 * This class builds JWT from the Authorization header.
 * </p>
 *
 * @since 1.0.0
 */
public class JWTCallbackHandler implements CarbonCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(JWTCallbackHandler.class);

    private CarbonMessage carbonMessage;

    private SignedJWT singedJWT;

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

        if (authorizationHeader.startsWith(CarbonSecurityConstants.HTTP_AUTHORIZATION_PREFIX_BEARER)) {

            String jwt = authorizationHeader.split("\\s+")[1];
            if (jwt != null && !jwt.trim().isEmpty()) {
                try {
                    singedJWT = SignedJWT.parse(jwt);

                    if (log.isDebugEnabled()) {
                        log.debug("JWTCallbackHandler will handle the request.");
                    }
                    return true;
                } catch (ParseException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while parsing the JWT token.", e);
                    }
                }
            }
        }
        return false;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        if (callbacks != null && callbacks.length > 0) {
            if (callbacks[0] instanceof CarbonCallback) {
                ((CarbonCallback) callbacks[0]).setContent(singedJWT);
            }
        }

    }
}
