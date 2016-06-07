package org.wso2.carbon.security.caas.api;

import org.wso2.carbon.messaging.CarbonMessage;

import javax.security.auth.callback.CallbackHandler;

/**
 * This interface is extended by all the carbon security callback handlers which relies on HTTP requests.
 *
 * @since 1.0.0
 */
public interface CarbonCallbackHandler extends CallbackHandler {

    String SUPPORTED_LOGIN_MODULE = "supported.login.module";

    /**
     * Set CarbonMessage.
     *
     * @param carbonMessage Carbon Message.
     */
    void setCarbonMessage(CarbonMessage carbonMessage);

    /**
     * Evaluate whether callback handler can process the callbacks.
     *
     * @return True if Callback handler can handle callbacks
     */
    boolean canHandle();

}
