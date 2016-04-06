package org.wso2.carbon.security.jaas;

import io.netty.handler.codec.http.HttpRequest;

import javax.security.auth.callback.CallbackHandler;

/**
 * This interface is extended by all the carbon security callback handlers which relies on HTTP requests.
 */
public interface HTTPCallbackHandler extends CallbackHandler {

    void setHTTPRequest(HttpRequest httpRequest);

    boolean canHandle();

}
