package org.wso2.carbon.security.jaas;

import io.netty.handler.codec.http.HttpRequest;

import javax.security.auth.callback.CallbackHandler;

public interface HTTPCallbackHandler extends CallbackHandler {

    void setHTTPRequest(HttpRequest httpRequest);

    boolean canHandle();

}
