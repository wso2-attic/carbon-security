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

package org.wso2.carbon.security.caas.test.osgi;

import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.kernel.context.PrivilegedCarbonContext;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.carbon.security.caas.api.ProxyCallbackHandler;
import org.wso2.carbon.security.caas.api.exception.CarbonSecurityAuthenticationException;
import org.wso2.carbon.security.caas.test.osgi.util.SecurityOSGiTestUtils;

import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import javax.inject.Inject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import static org.ops4j.pax.exam.CoreOptions.systemProperty;

/**
 * JAAS OSGI Tests.
 */

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class JAASTests {

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SecurityOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(systemProperty("java.security.auth.login.config").value(Paths.get(
                SecurityOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config").toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    @Test
    public void testBasicLogin() throws LoginException {

        PrivilegedCarbonContext.destroyCurrentContext();

        CarbonMessage carbonMessage = new DefaultCarbonMessage();
        carbonMessage.setHeader("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString("admin:admin".getBytes()));
        ProxyCallbackHandler callbackHandler = new ProxyCallbackHandler(carbonMessage);

        LoginContext loginContext = new LoginContext("CarbonSecurityBasicConfig", callbackHandler);

        loginContext.login();
        Assert.assertTrue(true);
    }

    @Test
    public void testBasicLoginFailure() {

        PrivilegedCarbonContext.destroyCurrentContext();

        CarbonMessage carbonMessage = new DefaultCarbonMessage();
        carbonMessage.setHeader("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString("admin:wrongpassword".getBytes()));

        ProxyCallbackHandler callbackHandler = new ProxyCallbackHandler(carbonMessage);

        LoginContext loginContext;

        try {
            loginContext = new LoginContext("CarbonSecurityBasicConfig", callbackHandler);
            loginContext.login();
            Assert.assertTrue(false, "Login succeeded for invalid credentials.");
        } catch (LoginException e) {

            if (e instanceof CarbonSecurityAuthenticationException) {
                Assert.assertTrue(true);
            } else {
                Assert.assertTrue(false, "Expected: " + CarbonSecurityAuthenticationException.class.getName() +
                                         " Caught: " + e.getClass().getName());
            }
        }
    }
}
