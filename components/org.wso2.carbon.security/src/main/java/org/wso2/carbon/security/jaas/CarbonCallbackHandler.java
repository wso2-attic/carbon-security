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

package org.wso2.carbon.security.jaas;

import io.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.List;

/**
 * The class {@code CarbonCallbackHandler} is an implementation {@code CarbonCallbackHandler}.
 * This callback handler is used for handling {@code CarbonCallback} type callbacks.
 */
public class CarbonCallbackHandler implements CallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(CarbonCallbackHandler.class);

    private HttpRequest httpRequest;

    public CarbonCallbackHandler(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        if (callbacks != null && callbacks.length > 0) {

            // in the case of NameCallback and PasswordCallback, both will get handled at once.
            boolean handled = false;

            for (Callback callback : callbacks) {
                // Specially handle NameCallback and PasswordCallback, since they are available OOTB
                if (callback instanceof NameCallback || callback instanceof PasswordCallback) {
                    if (!handled) {
                        List<HTTPCallbackHandler> callbackHandlers = CarbonSecurityDataHolder
                                .getInstance().getCallbackHandlers(CarbonSecurityConstants
                                                                           .USERNAME_PASSWORD_LOGIN_MODULE);
                        if (callbackHandlers != null && !callbackHandlers.isEmpty()) {
                            for (HTTPCallbackHandler callbackHandler : callbackHandlers) {
                                callbackHandler.setHTTPRequest(httpRequest);
                                if (callbackHandler.canHandle()) {
                                    callbackHandler.handle(callbacks);
                                    handled = true;
                                    break;
                                }
                            }
                        } else {
                            throw new UnsupportedCallbackException(callback);
                        }
                    }
                    // Handle CarbonCallbacks
                } else if (callback instanceof CarbonCallback) {
                    List<HTTPCallbackHandler> callbackHandlers = CarbonSecurityDataHolder.getInstance()
                            .getCallbackHandlers(((CarbonCallback) callback).getLoginModuleType());
                    if (callbackHandlers != null && !callbackHandlers.isEmpty()) {
                        for (HTTPCallbackHandler callbackHandler : callbackHandlers) {
                            callbackHandler.setHTTPRequest(httpRequest);
                            if (callbackHandler.canHandle()) {
                                callbackHandler.handle(new Callback[]{callback});
                                break;
                            }
                        }
                    } else {
                        throw new UnsupportedCallbackException(callback);
                    }

                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }
    }

}
