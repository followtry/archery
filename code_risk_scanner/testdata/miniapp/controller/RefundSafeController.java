package controller;

public class RefundSafeController {
    public void change(HttpServletRequest request) {
        String orderId = request.getParameter("orderId");
        String sql = "update refund set status = 1 where id = #{id} and buyer_id = #{buyerId}";
        jdbc.update(sql, orderId);
    }
}
