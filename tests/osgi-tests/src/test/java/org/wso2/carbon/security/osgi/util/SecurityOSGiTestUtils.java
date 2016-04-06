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

package org.wso2.carbon.security.osgi.util;

import org.ops4j.pax.exam.Option;
import org.wso2.carbon.osgi.test.util.CarbonSysPropConfiguration;
import org.wso2.carbon.osgi.test.util.OSGiTestConfigurationUtils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;

/**
 * This class contains the utility methods for carbon-security OSGI tests.
 */
public class SecurityOSGiTestUtils {

    /**
     * Returns the default list of PAX options needed for carbon-security OSGI test.
     *
     * @return list of Options
     */
    public static List<Option> getDefaultSecurityPAXOptions() {

        List<Option> defaultOptionList = new ArrayList<>();

        defaultOptionList.add(mavenBundle()
                                      .groupId("io.netty")
                                      .artifactId("netty-codec")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("io.netty")
                                      .artifactId("netty-buffer")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("io.netty")
                                      .artifactId("netty-codec-http")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("io.netty")
                                      .artifactId("netty-common")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("io.netty")
                                      .artifactId("netty-handler")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("io.netty")
                                      .artifactId("netty-transport")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("org.wso2.orbit.com.nimbusds")
                                      .artifactId("nimbus-jose-jwt")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("net.minidev.wso2")
                                      .artifactId("json-smart")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("org.wso2.carbon.datasources")
                                      .artifactId("org.wso2.carbon.datasource.core")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("org.wso2.carbon.jndi")
                                      .artifactId("org.wso2.carbon.jndi")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("org.wso2.carbon.security")
                                      .artifactId("org.wso2.carbon.security.boot")
                                      .versionAsInProject().noStart());
        defaultOptionList.add(mavenBundle()
                                      .groupId("org.wso2.carbon.security")
                                      .artifactId("org.wso2.carbon.security")
                                      .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                                      .groupId("commons-io.wso2")
                                      .artifactId("commons-io")
                                      .version("2.4.0.wso2v1"));
        defaultOptionList.add(mavenBundle()
                                      .groupId("com.zaxxer")
                                      .artifactId("HikariCP")
                                      .version("2.4.1"));
        defaultOptionList.add(mavenBundle()
                                      .groupId("com.h2database")
                                      .artifactId("h2")
                                      .version("1.4.191"));

        CarbonSysPropConfiguration sysPropConfiguration = new CarbonSysPropConfiguration();
        sysPropConfiguration.setCarbonHome(getCarbonHome());
        sysPropConfiguration.setServerKey("carbon-security");
        sysPropConfiguration.setServerName("WSO2 Carbon Security Server");
        sysPropConfiguration.setServerVersion("1.0.0");

        defaultOptionList = OSGiTestConfigurationUtils.getConfiguration(defaultOptionList, sysPropConfiguration);

        return defaultOptionList;
    }

    public static String getCarbonHome() {
        String currentDir = Paths.get("").toAbsolutePath().toString();
        Path carbonHome = Paths.get(currentDir, "target", "carbon-home");
        return carbonHome.toString();
    }
}

