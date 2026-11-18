package dao;

// tddl sharding logical table order_tab
public class OrderShardDao {
    public String byStatus(int status) {
        String sql = "select id, status from order_tab where status = #{status}";
        return sql;
    }

    public String byPrefix(String prefix) {
        String query = "select id from order_tab where substr(user_id, 1, 4) = #{prefix}";
        return query;
    }
}
