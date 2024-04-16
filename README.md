# This repository is no longer maintained.
Issue reports and pull requests will not be attended.

# Carbon Security
---

|  Branch | Build Status |
| :------------ |:-------------
| master      | [![Build Status](https://wso2.org/jenkins/buildStatus/icon?job=carbon-security)](https://wso2.org/jenkins/job/carbon-security) |


---
Carbon Security project provides authentication and authorization implementation for carbon products based on [JAAS](#).
## Features:
* JAAS based authentication.
* JAAS based authorization.
* Built in login modules
  * Username Password login module
  * JWT login module
* Mechanism to plug-in custom Login modules, callback handlers in an OSGi environment.

## Getting Started

### Authentication

Following are the steps to authenticate a user with an in-built login module.

Add following entry to the `bin/carbon.sh` file to enable JAAS based authentication,
```
    -Djava.security.auth.login.config="$CARBON_HOME/conf/security/carbon-jaas.config"\
```

Configure `carbon-jaas.config` file at `conf/security` to specify the login module to be used for authentication. For example if you wish to use the Username Password login module, `carbon-jaas.config` should look like below.

```
CarbonSecurityConfig {
   org.wso2.carbon.security.jaas.modules.UsernamePasswordLoginModule required;
};
```
Similarly for JWT login module, the following fully qualified class name can be used.

-  `org.wso2.carbon.security.jaas.modules.JWTLoginModule`

The following code snippet shows how to perfrom a login using JAAS.

```java
CallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);
LoginContext loginContext;
try {
    loginContext = new LoginContext("CarbonSecurityConfig", callbackHandler);
} catch (LoginException e) {
    //logic if initializing login context fails.
}
try {
    loginContext.login();
} catch (LoginException e) {
    //logic if login fails.
}
```

### Authorization

Following are the steps to authorize a principle from carbon authorization store.

Add following entries to the `bin/carbon.sh` file to enable JAAS based authentication,
```
    -Djava.security.manager \
    -Djava.security.policy="$CARBON_HOME/conf/security/security.policy" \
```

The following code snippet shows how to perform a authorization.

```java
    private boolean isAuthorized(Subject subject, final CarbonPermission requiredPermission) {

        final SecurityManager securityManager;

        if (System.getSecurityManager() == null) {
            securityManager = new SecurityManager();
        } else {
            securityManager = System.getSecurityManager();
        }

        try {
            Subject.doAsPrivileged(subject, (PrivilegedExceptionAction) () -> {
                securityManager.checkPermission(requiredPermission);
                return null;
            }, null);
            return true;
        } catch (AccessControlException ace) {
            return false;
        } catch (PrivilegedActionException pae) {
            return false;
        }
    }
```

## Download

Use Maven snippet:
````xml
<dependency>
    <groupId>org.wso2.carbon.security</groupId>
    <artifactId>org.wso2.carbon.security</artifactId>
    <version>${carbon.security.version}</version>
</dependency>
````

### Snapshot Releases

Use following Maven repository for snapshot versions of Carbon Security.

````xml
<repository>
    <id>wso2.snapshots</id>
    <name>WSO2 Snapshot Repository</name>
    <url>http://maven.wso2.org/nexus/content/repositories/snapshots/</url>
    <snapshots>
        <enabled>true</enabled>
        <updatePolicy>daily</updatePolicy>
    </snapshots>
    <releases>
        <enabled>false</enabled>
    </releases>
</repository>
````

### Released Versions

Use following Maven repository for released stable versions of Carbon Security.

````xml
<repository>
    <id>wso2.releases</id>
    <name>WSO2 Releases Repository</name>
    <url>http://maven.wso2.org/nexus/content/repositories/releases/</url>
    <releases>
        <enabled>true</enabled>
        <updatePolicy>daily</updatePolicy>
        <checksumPolicy>ignore</checksumPolicy>
    </releases>
</repository>
````
## Building From Source

Clone this repository first (`git clone https://github.com/wso2/carbon-security.git`) and use Maven install to build
`mvn clean install`.

## Contributing to Carbon Security Project

Pull requests are highly encouraged and we recommend you to create a [JIRA](https://wso2.org/jira/browse/CSECURITY) to discuss the issue or feature that you
 are contributing to.

## License

Carbon Security is available under the Apache 2 License.

## Copyright

Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
