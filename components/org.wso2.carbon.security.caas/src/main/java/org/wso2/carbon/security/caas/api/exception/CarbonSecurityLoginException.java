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

package org.wso2.carbon.security.caas.api.exception;

import javax.security.auth.login.LoginException;

/**
 * This Exception class is an extension of {@code LoginException} and the parent class for all carbon security login
 * exceptions. Additional constructors are provided to pass an int error code and a Throwable in order to throw a
 * more detailed exception to JAAS API consumers.
 */
public class CarbonSecurityLoginException extends LoginException {

    private static final long serialVersionUID = -3804371615491859728L;

    private Throwable cause;

    private int code = -1;

    public CarbonSecurityLoginException() {
        super();
    }

    public CarbonSecurityLoginException(String msg) {
        super(msg);
    }

    public CarbonSecurityLoginException(String msg, Throwable cause) {
        super(msg);
        this.cause = cause;
        initCause(cause);
    }

    public CarbonSecurityLoginException(int code, String msg, Throwable cause) {
        super(msg);
        this.code = code;
        this.cause = cause;
        initCause(cause);
    }

    public int getCode() {
        return code;
    }

    @Override
    public String getLocalizedMessage() {

        if (code == -1) {
            return super.getLocalizedMessage();
        } else {
            return code + " - " + getMessage();
        }
    }

    /**
     * CarbonSecurityLoginException error codes.
     */
    public enum ErrorMessage {

        INVALID_CREDENTIALS(10000, "Invalid user credentials."),
        CREDENTIAL_STORE_FAILURE(10001, "One or more credential stores produced errors while authenticating."),
        UNSUPPORTED_CALLBACK_EXCEPTION(10002, "Callback handler cannot handle given callbacks."),
        CALLBACK_HANDLE_EXCEPTION(10003, "Error while handling callbacks.");

        private final int code;
        private final String description;

        ErrorMessage(int code, String description) {
            this.code = code;
            this.description = description;
        }

        public int getCode() {
            return code;
        }

        public String getDescription() {
            return description;
        }

        @Override
        public String toString() {
            return code + " - " + description;
        }
    }

}
