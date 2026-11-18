package cache;

public class AdminCache {
    public void clean() {
        // 低频后台管理接口，仅值班使用
        jedis.keys("tmp:*");
    }
}
