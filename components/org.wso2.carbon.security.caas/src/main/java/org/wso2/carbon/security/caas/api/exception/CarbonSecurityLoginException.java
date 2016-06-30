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

    /**
     * Constructs a CarbonSecurityLoginException with no detail message. A detail
     * message is a String that describes this particular exception.
     */
    public CarbonSecurityLoginException() {
        super();
    }

    /**
     * Constructs a CarbonSecurityLoginException with the specified detail message.
     * A detail message is a String that describes this particular
     * exception.
     *
     * @param msg the detail message.
     */
    public CarbonSecurityLoginException(String msg) {
        super(msg);
    }

    /**
     * Creates a CarbonSecurityLoginException with the specified
     * detail message and cause.
     *
     * @param msg the detail message (which is saved for later retrieval
     *        by the {@code getMessage()} method).
     * @param cause the cause (which is saved for later retrieval by the
     *        {@code getCause()} method).  (A {@code null} value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     */
    public CarbonSecurityLoginException(String msg, Throwable cause) {
        super(msg);
        this.cause = cause;
        initCause(cause);
    }

    /**
     * Creates a CarbonSecurityLoginException with the specified
     * detail message and cause.
     *
     * @param code the code corresponding to the error (which is saved for later retrieval by the
     *        {@code getCode()} method).
     * @param msg the detail message (which is saved for later retrieval
     *        by the {@code getMessage()} method).
     */
    public CarbonSecurityLoginException(int code, String msg) {
        super(msg);
        this.code = code;
    }

    /**
     * Creates a CarbonSecurityLoginException with the specified
     * detail message and cause.
     *
     * @param code the code corresponding to the error (which is saved for later retrieval by the
     *        {@code getCode()} method).
     * @param msg the detail message (which is saved for later retrieval
     *        by the {@code getMessage()} method).
     * @param cause the cause (which is saved for later retrieval by the
     *        {@code getCause()} method).  (A {@code null} value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     */
    public CarbonSecurityLoginException(int code, String msg, Throwable cause) {
        super(msg);
        this.code = code;
        this.cause = cause;
        initCause(cause);
    }

    /**
     * Returns the error code corresponding to the error.
     * Returns -1 if the error code is unspecified.
     *
     * @return error code.
     */
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
     * Represent an enum which specifies errors used by CarbonSecurityLoginException
     * and it's sub types.
     */
    public enum CarbonSecurityErrorMessages {

        INVALID_CREDENTIALS(10000, "Invalid user credentials."),
        CREDENTIAL_STORE_FAILURE(10001, "One or more credential stores produced errors while authenticating."),
        UNSUPPORTED_CALLBACK_EXCEPTION(10002, "Callback handler cannot handle given callbacks."),
        CALLBACK_HANDLE_EXCEPTION(10003, "Error while handling callbacks.");

        private final int code;
        private final String description;

        /**
         * Creates a CarbonSecurityErrorMessages enum with the specified error code and detail message.
         *
         * @param code the code corresponding to the error (which is saved for later retrieval by the
         *        {@code getCode()} method).
         * @param description the detail message (which is saved for later retrieval
         *        by the {@code getDescription()} method).
         */
        CarbonSecurityErrorMessages(int code, String description) {
            this.code = code;
            this.description = description;
        }

        /**
         * Returns error code.
         * @return Error code as an int.
         */
        public int getCode() {
            return code;
        }

        /**
         * Returns error description.
         * @return Error description String.
         */
        public String getDescription() {
            return description;
        }

        @Override
        public String toString() {
            return code + " - " + description;
        }
    }

}
