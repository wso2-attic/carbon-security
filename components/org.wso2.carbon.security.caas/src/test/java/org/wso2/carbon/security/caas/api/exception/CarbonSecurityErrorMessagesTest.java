/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.security.caas.api.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

public class CarbonSecurityErrorMessagesTest {

    /**
     * This is a synthetic test just to keep the JaCoCo code coverage up. No real need to test enum.
     * @throws Exception
     */
    @Test
    public void testGetCode() throws Exception {
        for (CarbonSecurityLoginException.CarbonSecurityErrorMessages m :
                CarbonSecurityLoginException.CarbonSecurityErrorMessages
                .values()) {
            switch (m) {
            case INVALID_CREDENTIALS:
            case CREDENTIAL_STORE_FAILURE:
            case UNSUPPORTED_CALLBACK_EXCEPTION:
            case CALLBACK_HANDLE_EXCEPTION:
                break;

            default:
                Assert.fail("New enumeration value introduced: " + m);

            }
        }
    }
}
