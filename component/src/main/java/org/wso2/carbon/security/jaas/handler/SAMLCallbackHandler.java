package org.wso2.carbon.security.jaas.handler;

import io.netty.handler.codec.http.HttpRequest;
import org.wso2.carbon.security.jaas.HTTPCallbackHandler;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

public class SAMLCallbackHandler implements HTTPCallbackHandler {

    private HttpRequest httpRequest;

    @Override
    public String getSupportedLoginModuleType() {
        return CarbonSecurityConstants.SAML_LOGIN_MODULE;
    }

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
