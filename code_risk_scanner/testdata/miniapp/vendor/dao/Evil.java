package dao;

public class Evil {
    void ignored() {
        jedis.keys("user:*");
    }
}
