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

package org.wso2.carbon.security.caas.api.model;

import org.testng.annotations.Test;
import org.wso2.carbon.security.caas.api.CarbonPermission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;

public class UserTest {

    @Test
    public void testGetUsername() throws Exception {
        User testUser =  new User();
        assertNull(testUser.getUsername());
        testUser.setUsername("test");
        assertEquals(testUser.getUsername(), "test");
    }


    @Test
    public void testSetPassword() throws Exception {
        User testUser =  new User();
        assertNull(testUser.getPassword());
        testUser.setPassword("test");
        assertEquals(testUser.getPassword(), "test");
    }

    @Test
    public void testIsUserAuthorized() throws Exception {
        User testUser =  new User();
        testUser.setPermission("add,edit");

        CarbonPermission permission = new CarbonPermission("resource1", "add");

        assertFalse(testUser.isUserAuthorized(permission), "No permission given for resource 1");
    }

}