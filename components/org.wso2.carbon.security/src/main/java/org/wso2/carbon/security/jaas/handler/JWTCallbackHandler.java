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

package org.wso2.carbon.security.jaas.handler;

import com.nimbusds.jwt.SignedJWT;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.jaas.CarbonCallback;
import org.wso2.carbon.security.jaas.HTTPCallbackHandler;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;

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
public class JWTCallbackHandler implements HTTPCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(JWTCallbackHandler.class);

    private HttpRequest httpRequest;

    private SignedJWT singedJWT;

    @Override
    public void setHTTPRequest(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public boolean canHandle() {

        if (httpRequest == null || httpRequest.headers() == null
            || httpRequest.headers().get(HttpHeaders.Names.AUTHORIZATION) == null) {
            return false;
        }

        String authorizationHeader = httpRequest.headers().get(HttpHeaders.Names.AUTHORIZATION).trim();

        if (authorizationHeader.startsWith(CarbonSecurityConstants.HTTP_AUTHORIZATION_PREFIX_BEARER)) {

            String jwt = authorizationHeader.split(" ")[1];
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
