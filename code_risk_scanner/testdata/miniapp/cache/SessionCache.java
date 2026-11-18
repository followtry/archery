package cache;

import java.util.Map;

public class SessionCache {
    public Map<String, String> all(String key) {
        return jedis.hgetAll(key);
    }

    public void lock(String lockKey, String uuid) {
        jedis.setnx(lockKey, uuid);
    }

    public void unlock(String lockKey) {
        jedis.del(lockKey);
    }

    public void put(String key, String val) {
        jedis.setex(key, 3600, val);
    }

    public String get(String key) {
        String value = jedis.get(key);
        if (value == null) {
            return null;
        }
        return value;
    }

    public void danger() {
        jedis.keys("session:*");
    }
}
