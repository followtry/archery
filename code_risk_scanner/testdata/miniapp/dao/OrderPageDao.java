package dao;

// tddl sharding logical table order_tab
public class OrderPageDao {
    public String page(long userId, int offset, int pageSize) {
        String sql = "select id from order_tab where user_id = #{userId} limit #{offset}, #{pageSize}";
        return sql;
    }

    public String export(long userId) {
        String sql = "select id from order_tab where user_id = #{userId} limit 10000, 20";
        return sql;
    }
}
