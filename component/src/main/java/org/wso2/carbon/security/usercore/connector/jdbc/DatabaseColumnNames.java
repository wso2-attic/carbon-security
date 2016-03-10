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

package org.wso2.carbon.security.usercore.connector.jdbc;

/**
 * Names of the database table columns.
 */
public class DatabaseColumnNames {

    public static class Group {
        public static final String GROUP_UNIQUE_ID = "GROUP_UNIQUE_ID";
        public static final String GROUP_NAME = "GROUP_NAME";
    }

    public static class User {
        public static final String PASSWORD = "";
        public static final String USER_ID = "";
    }
}
