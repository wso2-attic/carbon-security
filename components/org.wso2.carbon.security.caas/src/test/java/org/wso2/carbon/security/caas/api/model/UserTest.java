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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class UserTest {

    private User testUser;

    @BeforeMethod
    protected void setUp() {
        testUser = new User();
    }

    @Test
    public void testGetUsername() throws Exception {
        assertNull(testUser.getUsername());
        testUser.setUsername("test");
        assertEquals(testUser.getUsername(), "test");
    }

    @Test
    public void testSetUsername() throws Exception {
         testGetUsername();
    }

    @Test
    public void testGetPassword() throws Exception {

    }

    @Test
    public void testSetPassword() throws Exception {

    }

    @Test
    public void testGetPermission() throws Exception {

    }

    @Test
    public void testSetPermission() throws Exception {

    }

    @Test
    public void testIsUserAuthorized() throws Exception {

    }

}