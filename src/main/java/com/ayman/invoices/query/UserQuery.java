package com.ayman.invoices.query;

public class UserQuery {
    public static final String COUNT_USER_EMAIL_QUERY = "SELECT COUNT(*) FROM Users WHERE email = :email";
    public static final String INSERT_USER_QUERY =
            "INSERT INTO users (first_name, last_name, email, password)" +
                    " VALUES (:firstName, :lastName, :email, :password)" ;
    public static String INSERT_ACCOUNT_VERIFICATION_URL_QUERY="INSERT INTO AccountVerifications(user_id, url) VALUES (:userId, :url)";
}
