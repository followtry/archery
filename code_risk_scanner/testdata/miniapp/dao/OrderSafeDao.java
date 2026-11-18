package dao;

// tddl sharding logical table order_tab
public class OrderSafeDao {
    public String byUser(long userId, int status) {
        String sql = "select id, status from order_tab where user_id = #{userId} and status = #{status}";
        String countSql = "select count(*) from order_tab where user_id = #{userId}";
        return sql + countSql;
    }
}
