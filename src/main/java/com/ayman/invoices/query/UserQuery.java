package com.ayman.invoices.query;
public class UserQuery {
    public static final String COUNT_USER_EMAIL_QUERY = "SELECT COUNT(*) FROM Users WHERE email = :email";
    public static final String INSERT_USER_QUERY =
            "INSERT INTO users (first_name, last_name, email, password)" +
                    " VALUES (:firstName, :lastName, :email, :password)" ;
    public static final String SELECT_USER_BY_EMAIL_QUERY = "SELECT * FROM Users WHERE email = :email";
    public static final String SELECT_USER_BY_CODE_QUERY = "SELECT * FROM Users WHERE id = (SELECT user_id FROM TwoFactorVerifications WHERE code = :code)";
    public static final String DELETE_PASSWORD_VERIFICATION_BY_USER_ID_QUERY = "DELETE FROM ResetPasswordVerifications WHERE user_id = :userId";
    public static final String INSERT_PASSWORD_VERIFICATION_QUERY = "INSERT INTO ResetPasswordVerifications (user_id, url, expression_date) VALUES (:userId, :url, :expirationDate)";
    public static final String SELECT_USER_BY_PASSWORD_URL_QUERY = "SELECT * FROM Users WHERE id =(SELECT user_id FROM ResetPasswordVerifications WHERE url = :url)";
    public static final String UPDATE_USER_ENABLED_QUERY = "UPDATE Users SET enabled = :enabled WHERE id = :id";
    public static String INSERT_ACCOUNT_VERIFICATION_URL_QUERY="INSERT INTO AccountVerifications(user_id, url) VALUES (:userId, :url)";
    public static String DELETE_TWO_FACTOR_VERIFICATION_CODE_BY_USER_ID_QUERY = "DELETE FROM TwoFactorVerifications WHERE user_id = :id";
    public static String INSERT_VERIFICATION_CODE_QUERY = "INSERT INTO TwoFactorVerifications (user_id, code, expression_date) VALUES (:userId, :code, :expression_date)";
    public static final String DELETE_CODE = "DELETE FROM TwoFactorVerifications WHERE code = :code";
    public static final String SELECT_CODE_EXPIRATION_DATE_QUERY = "SELECT expression_date < NOW() AS is_expired FROM TwoFactorVerifications WHERE code =:code";
    public static final String SELECT_EXPIRATION_BY_URL = "SELECT expression_date < NOW() AS is_expired FROM ResetPasswordVerifications WHERE url =:url";
    public static final String UPDATE_USER_PASSWORD_BY_URL_QUERY ="UPDATE Users SET password = :password WHERE id = (SELECT user_id FROM ResetPasswordVerifications WHERE url = :url)" ;
    public static final String DELETE_VERIFICATION_BY_URL_QUERY = "DELETE FROM ResetPasswordVerifications WHERE url = :url";
    public static final String SELECT_USER_BY_ACCOUNT_URL_QUERY =  "SELECT * FROM Users WHERE id =(SELECT user_id FROM AccountVerifications WHERE url = :url)";

}
