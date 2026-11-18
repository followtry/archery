package dao;

// tddl sharding logical table order_tab
public class OrderStarDao {
    public String all(long userId) {
        String sql = "select * from order_tab where user_id = #{userId}";
        return sql;
    }
}
