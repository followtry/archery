package cache;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class SessionSafeCache {
    public void lock(String key, String uuid) {
        jedis.set(key, uuid, "NX", "PX", 30000);
    }

    public void unlock(String key, String uuid) {
        String lua = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
        jedis.eval(lua, Arrays.asList(key), Arrays.asList(uuid));
    }

    public void put(String key, String val) {
        int ttl = 3600 + ThreadLocalRandom.current().nextInt(300);
        jedis.setex(key, ttl, val);
    }

    public String get(String key) {
        String value = jedis.get(key);
        if (value == null) {
            jedis.setex(key, 60, "");
            return null;
        }
        return value;
    }

    public void all(String key) {
        jedis.hscan(key, "0");
    }
}
