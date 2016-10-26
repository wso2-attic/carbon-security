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

package org.wso2.carbon.security.caas.tests.usercore;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.internal.CarbonSecurityComponent;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.internal.config.StoreConfigBuilder;
import org.wso2.carbon.security.caas.internal.config.domain.DomainConfig;
import org.wso2.carbon.security.caas.internal.config.domain.DomainConfigBuilder;
import org.wso2.carbon.security.caas.tests.usercore.constant.UserConstants;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.claim.FileBasedMetaClaimStore;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimStore;
import org.wso2.carbon.security.caas.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.CarbonSecurityConfigException;
import org.wso2.carbon.security.caas.user.core.exception.CarbonSecurityDataHolderException;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.DomainConfigException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.CredentialStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;
import org.wso2.carbon.security.caas.user.core.store.IdentityStoreImpl;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.caas.userstore.filebased.connector.FileBasedAuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.userstore.filebased.connector.FileBasedCredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.userstore.filebased.connector.FileBasedIdentityStoreConnectorFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

/**
 * Tests specific for permission model implementation.
 */
@PrepareForTest(CarbonSecurityDataHolder.class)
public class PermissionTest extends PowerMockTestCase {

    /**
     * Logger instance for PermissionTest class
     */
    private static final Logger logger = LoggerFactory.getLogger(PermissionTest.class);

    /**
     * Carbon security data holder to hold references.
     */
    @Mock
    private CarbonSecurityDataHolder carbonSecurityDataHolder;

    /**
     * Initialise mocks at test start.
     */
    @BeforeClass
    public void setup() {

        MockitoAnnotations.initMocks(this);
    }

    /**
     * Initialise instances which are required by the tests.
     */
    @BeforeMethod
    public void init() {

        initCarbonSecurityDataHolder();
    }

    /**
     * Test for authenticating an user.
     *
     * @throws CredentialStoreException          CredentialStoreException on initialising credential store
     * @throws IdentityStoreException            IdentityStoreException on identity store initialisation
     * @throws AuthorizationStoreException       AuthorizationStoreException on authorisation store initialisation
     * @throws AuthenticationFailure             AuthenticationFailure when the user authentication failes
     * @throws UserNotFoundException             UserNotFoundException when the identity store user is not found
     * @throws CarbonSecurityDataHolderException When getting domain configuration from CarbonSecurityDataHolder
     * @throws DomainConfigException             When getting or creating domain configuration
     * @throws NoSuchMethodException             When the stated method is not found
     * @throws InvocationTargetException         When error occurred invoking the method
     * @throws IllegalAccessException            When the invoking method is not accessible
     * @throws CarbonSecurityConfigException    on error in reading file
     */
    @Test
    public void authenticateUser() throws AuthorizationStoreException, IdentityStoreException,
            CredentialStoreException, UserNotFoundException, AuthenticationFailure, InvocationTargetException,
            NoSuchMethodException, DomainConfigException, IllegalAccessException, CarbonSecurityDataHolderException,
            CarbonSecurityConfigException {

        char[] password = new char[]{'a', 'd', 'm', 'i', 'n'};

        logger.info(String
                .format("Starting user authentication via %s:%s",
                        UserConstants.USER_NAME, String.valueOf(password)));

        StoreConfig storeConfig = createStoreConfig();
        MetaClaimStore metaClaimStore = new FileBasedMetaClaimStore();
        Mockito.when(CarbonSecurityDataHolder.getInstance().getMetaClaimStore())
                .thenReturn(metaClaimStore);

        DomainManager domainManager = initialiseDomainManager(storeConfig);
        initCarbonRealmService(domainManager, storeConfig);

        // User builder initialisation
        User user = Mockito.mock(User.class);
        Mockito.when(user.getUserId()).thenReturn(UserConstants.USER_NAME);

        IdentityStore identityStore = CarbonSecurityDataHolder
                .getInstance().getCarbonRealmService().getIdentityStore();
        Mockito.when(identityStore.getUser(Mockito.anyString())).thenReturn(user);

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        NameCallback nameCallback = new NameCallback("username");

        nameCallback.setName(UserConstants.USER_NAME);
        passwordCallback.setPassword(password);

        callbacks[0] = passwordCallback;
        callbacks[1] = nameCallback;

        AuthenticationContext authenticationContext =
                CarbonSecurityDataHolder.getInstance().getCarbonRealmService()
                        .getCredentialStore().authenticate(callbacks);

        Assert.assertNotNull(authenticationContext);

        logger.info("User authentication test completed");
    }

    /**
     * Initialise carbon security data holder.
     */
    private void initCarbonSecurityDataHolder() {

        PowerMockito.mockStatic(CarbonSecurityDataHolder.class);
        Mockito.when(CarbonSecurityDataHolder.getInstance()).thenReturn(carbonSecurityDataHolder);
    }

    /**
     * Initialise domain manager using domain-config
     *
     * @param storeConfig Store configuration
     * @return DomainManager initialised domain manager
     * @throws CarbonSecurityDataHolderException When getting domain configuration from CarbonSecurityDataHolder
     * @throws CarbonSecurityConfigException    on error in reading file
     * @throws NoSuchMethodException             When the stated method is not found
     * @throws InvocationTargetException         When error occurred invoking the method
     * @throws IllegalAccessException            When the invoking method is not accessible
     */
    private DomainManager initialiseDomainManager(StoreConfig storeConfig)
            throws CarbonSecurityDataHolderException, NoSuchMethodException,
            InvocationTargetException, IllegalAccessException, CarbonSecurityConfigException {

        DomainConfig domainConfig = DomainConfigBuilder.getDomainConfig();

        Mockito.when(CarbonSecurityDataHolder.getInstance().getDomainConfig())
                .thenReturn(domainConfig);

        Method method = CarbonSecurityComponent.class
                .getDeclaredMethod("createDomainManagerFromConfig", DomainConfig.class, StoreConfig.class);
        method.setAccessible(true);

        CarbonSecurityComponent c = new CarbonSecurityComponent();

        return (DomainManager) method.invoke(c, domainConfig, storeConfig);
    }

    /**
     * Initialise carbon realm service.
     *
     * @param domainManager DomainManager
     * @param storeConfig   StoreConfig
     * @throws AuthorizationStoreException AuthorizationStoreException on authorisation store initialisation
     * @throws CredentialStoreException    CredentialStoreException on initialising credential store
     * @throws IdentityStoreException      IdentityStoreException on identity store initialisation
     */
    private void initCarbonRealmService(DomainManager domainManager, StoreConfig storeConfig)
            throws CredentialStoreException, IdentityStoreException, AuthorizationStoreException {

        AuthorizationStoreImpl authorizationStore = new AuthorizationStoreImpl();
        CredentialStoreImpl credentialStore = new CredentialStoreImpl();
        IdentityStoreImpl identityStore = Mockito.mock(IdentityStoreImpl.class);

        credentialStore.init(domainManager, storeConfig.getCredentialConnectorConfigMap());
        identityStore.init(domainManager);
        authorizationStore.init(storeConfig.getAuthorizationConnectorConfigMap());

        // Add carbon realm service to the carbon realm service implementation
        CarbonRealmServiceImpl<IdentityStoreImpl, CredentialStoreImpl> realmService =
                new CarbonRealmServiceImpl<>(identityStore, credentialStore, authorizationStore);
        Mockito.when(CarbonSecurityDataHolder.getInstance().getCarbonRealmService())
                .thenReturn(realmService);
    }

    /**
     * Initialise store configuration.
     *
     * @return StoreConfig
     * @throws CarbonSecurityConfigException on error in reading file
     */
    private StoreConfig createStoreConfig() throws CarbonSecurityConfigException {

        StoreConfig storeConfig = StoreConfigBuilder.getStoreConfig();

        // Adding factories to realm service which is done by OSGI at runtime
        // Credential store
        Map<String, CredentialStoreConnectorFactory> credentialStoreConnectorFactoryMap = new HashMap<>();
        storeConfig.getCredentialConnectorConfigMap().values().forEach(credentialStoreConnectorConfig -> {

            // Inject store file path
            String storeFile = credentialStoreConnectorConfig.getProperties().getProperty("storeFile");
            credentialStoreConnectorConfig.getProperties().setProperty("storeFile",
                    Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), storeFile).toString());

            credentialStoreConnectorFactoryMap.put(credentialStoreConnectorConfig.getConnectorType(),
                    new FileBasedCredentialStoreConnectorFactory());
        });

        Mockito.when(CarbonSecurityDataHolder.getInstance().getCredentialStoreConnectorFactoryMap())
                .thenReturn(credentialStoreConnectorFactoryMap);

        // Identity Server
        Map<String, IdentityStoreConnectorFactory> identityStoreConnectorFactoryMap = new HashMap<>();
        storeConfig.getIdentityConnectorConfigMap().values().forEach(identityStoreConnectorConfig -> {

            // Inject store file path
            String storeFile = identityStoreConnectorConfig.getProperties().getProperty("storeFile");
            identityStoreConnectorConfig.getProperties().setProperty("storeFile",
                    Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), storeFile).toString());

            identityStoreConnectorFactoryMap.put(identityStoreConnectorConfig.getConnectorType(),
                    new FileBasedIdentityStoreConnectorFactory());
        });

        Mockito.when(CarbonSecurityDataHolder.getInstance().getIdentityStoreConnectorFactoryMap())
                .thenReturn(identityStoreConnectorFactoryMap);

        // Authorization store
        Map<String, AuthorizationStoreConnectorFactory> authorizationStoreConnectorFactoryMap = new HashMap<>();
        storeConfig.getAuthorizationConnectorConfigMap().values().forEach(authorizationStoreConnectorConfig ->
                authorizationStoreConnectorFactoryMap.put(authorizationStoreConnectorConfig.getConnectorType(),
                        new FileBasedAuthorizationStoreConnectorFactory()));

        Mockito.when(CarbonSecurityDataHolder.getInstance().getAuthorizationStoreConnectorFactoryMap())
                .thenReturn(authorizationStoreConnectorFactoryMap);

        return storeConfig;
    }
}
