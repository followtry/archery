package cache

import "github.com/go-redis/redis/v8"

func All(ctx context.Context, rdb *redis.Client, key string) {
	rdb.HGetAll(ctx, key)
}

func Lock(ctx context.Context, rdb *redis.Client, key string) {
	rdb.SetNX(ctx, key, "1", 0)
}
