/*
*  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.security.caas.test.unit;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.CredentialStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

/**
 * Tests specific for the domain model implementation.
 */
public class DomainTests {

    @Mock
    private CredentialStoreConnector credentialStoreConnector;

    @Mock
    private IdentityStore identityStore;

    private CredentialStore credentialStore = new CredentialStoreImpl();

    /**
     * Logger instance for DomainTests class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DomainTests.class);

    @BeforeClass
    public void setup() {

        logger.info("-------------------------------------------------");
        logger.info("-------------------------------------------------");
        logger.info("Starting Domain Tests");
        MockitoAnnotations.initMocks(this);
    }

    /**
     * Test to check weather the domains are properly created from config.
     */
    @Test
    public void loadDomainFromConnectorConfig() throws AuthenticationFailure, CredentialStoreException,
            IdentityStoreException, UserNotFoundException {

        authenticateUser();
    }

    @AfterClass
    public void teardown() {
        logger.info("Finishing Domain Tests");
        logger.info("-------------------------------------------------");
        logger.info("-------------------------------------------------");
    }

    /**
     * Authenticate a user.
     *
     * @throws AuthenticationFailure    Exception upon failing to authenticate
     * @throws CredentialStoreException Exception in the credential store
     * @throws IdentityStoreException   Exception in the identity store
     * @throws UserNotFoundException    Exception if the user is not found
     */
    private void authenticateUser() throws AuthenticationFailure, CredentialStoreException,
            IdentityStoreException, UserNotFoundException {

        Mockito.when(credentialStoreConnector.authenticate(Mockito.any(Callback[].class)))
                .thenReturn(new User.UserBuilder());

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        NameCallback nameCallback = new NameCallback("username");

        nameCallback.setName("admin");
        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;
        callbacks[1] = nameCallback;

        User user = Mockito.mock(User.class);
        Mockito.when(user.getUserId()).thenReturn("admin");

        Mockito.doReturn(user).when(identityStore).getUser(callbacks);

        logger.info("Authenticating user admin for password admin");
        AuthenticationContext authenticationContext = credentialStore.authenticate(callbacks);

        Assert.assertNotNull(authenticationContext);
    }
}
