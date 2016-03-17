package org.wso2.carbon.security.usercore.util;


import java.sql.Connection;
import java.sql.SQLException;

/**
 * Created by jayanga on 3/17/16.
 */
public class UnitOfWork implements AutoCloseable {

    private Connection connection;

    private UnitOfWork() throws SQLException {
    }

    public static UnitOfWork beginTransaction(Connection connection) throws SQLException {

        UnitOfWork unitOfWork = new UnitOfWork();
        connection.setAutoCommit(false);
        unitOfWork.connection = connection;

        return unitOfWork;
    }

    public Connection getConnection() {
        return connection;
    }

    @Override
    public void close() throws SQLException {
        connection.commit();
        connection.close();
    }
}
