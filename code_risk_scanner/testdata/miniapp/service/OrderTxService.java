package service;

import java.util.List;

public class OrderTxService {
    @Transactional
    public void saveAll(List<Order> orders) {
        for (Order order : orders) {
            orderMapper.update(order);
        }
    }
}
