package controller;

public class PayNotifySafeController {
    @PostMapping("/pay/notify")
    public void onNotify(String body, String sign) {
        rsa.verify(body, sign);
        String sql = "update pay_order set status = 1 where order_id = #{orderId}";
        jdbc.update(sql);
    }
}
