package dao;

public class OrderInDao {
    public String build(String ids) {
        String sql = "select id from order_tab where user_id in (" + ids + ")";
        return sql;
    }
}
