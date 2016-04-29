package org.wso2.carbon.security.caas.jaas;

import io.netty.handler.codec.http.HttpRequest;

import javax.security.auth.callback.CallbackHandler;

/**
 * This interface is extended by all the carbon security callback handlers which relies on HTTP requests.
 *
 * @since 1.0.0
 */
public interface HTTPCallbackHandler extends CallbackHandler {

    String SUPPORTED_LOGIN_MODULE = "supported.login.module";

    /**
     * Set HTTPRequest
     *
     * @param httpRequest HTTP Request.
     */
    void setHTTPRequest(HttpRequest httpRequest);

    /**
     * Evaluate whether callback handler can process the callbacks
     *
     * @return True if Callback handler can handle callbacks
     */
    boolean canHandle();

}
