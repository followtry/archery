package controller;

public class PayNotifyController {
    @PostMapping("/pay/notify")
    public void onNotify(String body) {
        String sql = "update pay_order set status = 1 where order_id = #{orderId}";
        jdbc.update(sql);
    }
}
