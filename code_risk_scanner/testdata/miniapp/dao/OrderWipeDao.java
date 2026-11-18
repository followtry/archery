package dao;

public class OrderWipeDao {
    public String reset() {
        String sql = "update order_tab set status = 0";
        return sql;
    }
}
