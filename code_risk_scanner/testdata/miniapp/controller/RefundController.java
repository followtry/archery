package controller;

public class RefundController {
    public void change(HttpServletRequest request) {
        String orderId = request.getParameter("orderId");
        String sql = "update refund set status = 1 where id = #{id}";
        jdbc.update(sql, orderId);
    }
}
