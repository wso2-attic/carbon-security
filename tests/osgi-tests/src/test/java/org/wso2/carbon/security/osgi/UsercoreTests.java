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

package org.wso2.carbon.security.osgi;

import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.osgi.test.util.CarbonSysPropConfiguration;
import org.wso2.carbon.osgi.test.util.OSGiTestConfigurationUtils;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.usercore.exception.AuthenticationFailure;
import org.wso2.carbon.security.usercore.exception.CredentialStoreException;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.service.RealmService;
import org.wso2.carbon.security.usercore.store.CredentialStore;
import org.wso2.carbon.security.usercore.store.IdentityStore;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Carbon Security OSGI tests.
 */

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class UsercoreTests {

    private static final String DEFAULT_USERNAME = "admin";
    private static final String DEFAULT_USER_ID = "41dadd2aea6e11e59ce95e5517507c66";
    private static final String DEFAULT_GROUP_ID = "a422aa98ecf411e59ce95e5517507c66";

    @Inject
    private BundleContext bundleContext;

    @Inject
    private RealmService realmService;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = new ArrayList<>();
        optionList.add(mavenBundle()
                .groupId("io.netty")
                .artifactId("netty-codec")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("io.netty")
                .artifactId("netty-buffer")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("io.netty")
                .artifactId("netty-codec-http")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("io.netty")
                .artifactId("netty-common")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("io.netty")
                .artifactId("netty-handler")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("io.netty")
                .artifactId("netty-transport")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.orbit.com.nimbusds")
                .artifactId("nimbus-jose-jwt")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("net.minidev.wso2")
                .artifactId("json-smart")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.datasources")
                .artifactId("org.wso2.carbon.datasource.core")
                .versionAsInProject());
        optionList.add(mavenBundle()
                 .groupId("org.wso2.carbon.jndi")
                 .artifactId("org.wso2.carbon.jndi")
                 .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.security")
                .artifactId("org.wso2.carbon.security")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("commons-io.wso2")
                .artifactId("commons-io")
                .version("2.4.0.wso2v1"));
        optionList.add(mavenBundle()
                .groupId("com.zaxxer")
                .artifactId("HikariCP")
                .version("2.4.1"));
        optionList.add(mavenBundle()
                .groupId("com.h2database")
                .artifactId("h2")
                .version("1.4.191"));

        String currentDir = Paths.get("").toAbsolutePath().toString();
        Path carbonHome = Paths.get(currentDir, "target", "carbon-home");

        CarbonSysPropConfiguration sysPropConfiguration = new CarbonSysPropConfiguration();
        sysPropConfiguration.setCarbonHome(carbonHome.toString());
        sysPropConfiguration.setServerKey("carbon-security");
        sysPropConfiguration.setServerName("WSO2 Carbon Security Server");
        sysPropConfiguration.setServerVersion("1.0.0");

        optionList = OSGiTestConfigurationUtils.getConfiguration(optionList, sysPropConfiguration);

        return optionList.toArray(new Option[optionList.size()]);
    }

    /* Authentication flow */

    @Test
    public void testAuthentication() throws CredentialStoreException, IdentityStoreException, AuthenticationFailure {

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        NameCallback nameCallback = new NameCallback("username");

        nameCallback.setName("admin");
        passwordCallback.setPassword(new char[] {'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;
        callbacks[1] = nameCallback;

        CredentialStore authManager = realmService.getCredentialStore();

        assertNotNull(authManager.authenticate(callbacks));
    }

    /* Identity management flow */

    @Test
    public void testIsUserInGroupValid() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        assertTrue(identityStore.isUserInGroup(DEFAULT_USER_ID, DEFAULT_GROUP_ID));
    }

    @Test
    public void testAddUserValid() throws IdentityStoreException {

        String username = "jayangak";
        char [] password = {'t', 'e', 's', 't'};

        Map<String, String> userClaims = new HashMap<>();
        userClaims.put("First Name", "Jayanga");
        userClaims.put("Last Name", "Kaushalya");

        List<String> groups = new ArrayList<>();
        groups.add("is");

        IdentityStore identityStore = realmService.getIdentityStore();
        User user = identityStore.addUser(username, userClaims, password, groups);

        assertNotNull(user);
    }

    @Test
    public void testGetUserFromUsername() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        User user  = identityStore.getUser(DEFAULT_USERNAME);
        assertNotNull(user);
    }

    @Test
    public void testGetUserFromUserId() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        User user  = identityStore.getUserfromId(DEFAULT_USER_ID);
        assertNotNull(user);
    }
}
