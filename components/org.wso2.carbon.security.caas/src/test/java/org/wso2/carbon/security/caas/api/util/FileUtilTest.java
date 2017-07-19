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

package org.wso2.carbon.security.caas.api.util;

import org.testng.annotations.Test;
import org.wso2.carbon.security.caas.api.model.User;
import org.wso2.carbon.security.caas.api.model.UsersFile;
import sun.security.action.GetPropertyAction;

import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Tests for Reading and writing config files
 */
public class FileUtilTest {

    @Test
    public void testReadConfigFiles() throws Exception {
        URL url = FileUtilTest.class.getClassLoader().getResource("conf/users/");
        Path path = Paths.get(url.getPath());
        List<UsersFile> userFiles = FileUtil.readConfigFiles(path, UsersFile.class, "*.yaml");
        assertEquals(userFiles.size(), 2);
    }

    @Test
    public void testReadConfigFiles_IncorrectBean() throws Exception {
        URL url = FileUtilTest.class.getClassLoader().getResource("conf/users/");
        Path path = Paths.get(url.getPath());
        try {
            FileUtil.readConfigFiles(path, User.class, "*.yaml");
            fail("There should be an exception parsing wrong bean");
        } catch (Throwable t) {
            assertTrue(true);
        }
    }

    @Test
    public void testWriteConfigFile() throws Exception {
        URL url = FileUtilTest.class.getClassLoader().getResource("conf/users/");
        Path path = Paths.get(url.getPath());
        List<UsersFile> userFiles = FileUtil.readConfigFiles(path, UsersFile.class, "*.yaml");

        File tmpdir = new File(AccessController.doPrivileged(new GetPropertyAction("java.io.tmpdir")));
        Path tempDirPath = Paths.get(tmpdir.getPath(), "CAAS_UNIT_TEST", "" + System.currentTimeMillis());
        File testFilesDir = new File(tempDirPath.toString());
        if (!testFilesDir.mkdirs()) {
            fail("Temporary directory creation failed: " + tempDirPath);
        }

        Path writtenFilePath = Paths.get(tempDirPath.toString(), "test.yaml");
        File writtenFile = new File(writtenFilePath.toString());
        writtenFile.createNewFile();
        FileUtil.writeConfigFile(writtenFilePath, userFiles.get(0));

        UsersFile userFile = FileUtil.readConfigFile(writtenFilePath, UsersFile.class);
        assertNotNull(userFile);

        writtenFile.delete();
    }
}
