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

import io.netty.handler.codec.http.HttpRequest;
import org.wso2.carbon.security.jaas.HTTPCallbackHandler;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * <p>
 * This class builds SAML Assertion from the Authorization header
 * </p>
 */
public class SAMLCallbackHandler implements HTTPCallbackHandler {

    private HttpRequest httpRequest;

    @Override
    public void setHTTPRequest(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public boolean canHandle() {
        return false;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

    }

}
