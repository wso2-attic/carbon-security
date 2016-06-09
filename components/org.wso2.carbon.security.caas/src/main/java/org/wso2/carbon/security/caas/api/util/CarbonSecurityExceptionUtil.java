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

package org.wso2.carbon.security.caas.api.util;

import org.wso2.carbon.security.caas.api.exception.CarbonSecurityAuthenticationException;
import org.wso2.carbon.security.caas.api.exception.CarbonSecurityLoginException;
import org.wso2.carbon.security.caas.api.exception.CarbonSecurityServerException;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;

import static org.wso2.carbon.security.caas.api.exception.CarbonSecurityLoginException.ErrorMessage;

/**
 * Util class for exception handling.
 */
public class CarbonSecurityExceptionUtil {


    /**
     * Builds a CarbonSecurityLoginException sub type based on the content of the AuthenticationFailure stack trace.
     *
     * @param authenticationFailure
     * @return CarbonSecurityLoginException
     */
    public static CarbonSecurityLoginException buildLoginException(AuthenticationFailure authenticationFailure) {

        Throwable[] suppressed = authenticationFailure.getSuppressed();

        for (Throwable t : suppressed) {
            // Checks whether AuthenticationFailure has suppressed a CredentialStoreException and returns
            // a CarbonSecurityServerException if true.
            if (t instanceof CredentialStoreException) {
                return new CarbonSecurityServerException(ErrorMessage.CREDENTIAL_STORE_FAILURE.getCode(),
                                                         ErrorMessage.CREDENTIAL_STORE_FAILURE.getDescription(),
                                                         authenticationFailure);
            }
        }

        return new CarbonSecurityAuthenticationException(ErrorMessage.INVALID_CREDENTIALS.getCode(),
                                                         ErrorMessage.INVALID_CREDENTIALS.getDescription(),
                                                         authenticationFailure);
    }

}
