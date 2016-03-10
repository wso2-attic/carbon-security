package org.wso2.carbon.security.jaas;

import io.netty.handler.codec.http.HttpRequest;

import javax.security.auth.callback.CallbackHandler;

public interface HTTPCallbackHandler extends CallbackHandler {

    public abstract String getSupportedLoginModuleType();

    public abstract void setHTTPRequest(HttpRequest httpRequest);

    public abstract boolean canHandle();

}
