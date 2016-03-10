package org.wso2.carbon.security.jaas.handler;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import org.wso2.carbon.security.jaas.HTTPCallbackHandler;
import org.wso2.carbon.security.jaas.util.CarbonSecurityConstants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BasicAuthCallbackHandler implements HTTPCallbackHandler {

    private HttpRequest httpRequest;

    private String username;

    private char[] password;

    @Override
    public String getSupportedLoginModuleType() {
        return CarbonSecurityConstants.USERNAME_PASSWORD_LOGIN_MODULE;
    }

    @Override
    public void setHTTPRequest(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public boolean canHandle() {

        if (httpRequest != null) {

            HttpHeaders headers = httpRequest.headers();
            if (headers != null) {

                String authorizationHeader = headers.get(HttpHeaders.Names.AUTHORIZATION);
                if (authorizationHeader != null && !authorizationHeader.isEmpty()) {

                    if (authorizationHeader.trim().startsWith(CarbonSecurityConstants
                                                                      .HTTP_AUTHORIZATION_PREFIX_BASIC)) {

                        String credentials = authorizationHeader.trim().split(" ")[1];
                        byte[] decodedByte = credentials.getBytes(Charset.forName(StandardCharsets.UTF_8.name()));
                        String authDecoded = new String(Base64.getDecoder().decode(decodedByte),
                                                        Charset.forName(StandardCharsets.UTF_8.name()));
                        String[] authParts = authDecoded.split(":");
                        if (authParts.length == 2) {
                            username = authParts[0];
                            password = authParts[1].toCharArray();
                            return true;
                        }
                    }
                }
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
