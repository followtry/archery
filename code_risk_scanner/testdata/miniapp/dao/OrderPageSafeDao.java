package dao;

// tddl sharding logical table order_tab
public class OrderPageSafeDao {
    public String page(long userId, int offset, int pageSize) {
        if (offset > 5000) {
            throw new IllegalArgumentException("offset must be <= 5000");
        }
        String sql = "select id from order_tab where user_id = #{userId} limit #{offset}, #{pageSize}";
        return sql;
    }
}
