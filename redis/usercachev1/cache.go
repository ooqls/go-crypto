package usercachev1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/braumsmilk/go-log"
	"github.com/braumsmilk/go-token/redis"
	"github.com/go-redis/cache/v8"
	"go.uber.org/zap"
)

var l *zap.Logger = log.NewLogger("userNameCache")

type UserMetadataCache interface {
	GetUser(id int) map[string]string
	AddUser(id int, meta map[string]string)
}

func NewRedisCache() *RedisCache {
	r := redis.NewRedis()
	return &RedisCache{
		c: *cache.New(&cache.Options{
			Redis:      r,
			LocalCache: cache.NewTinyLFU(100, time.Hour),
		}),
	}
}

type RedisCache struct {
	c cache.Cache
}

func (r *RedisCache) GetUser(id int) map[string]string {
	key := fmt.Sprintf("username-%d", id)
	var meta map[string]string
	err := r.c.Get(context.Background(), key, &meta)
	if err != nil {
		if errors.Is(err, cache.ErrCacheMiss) {
			return nil
		}
		l.Warn("failed to get username from redis cache", zap.Error(err))
		return nil
	}

	return meta
}

func (r *RedisCache) AddUser(id int, metadata map[string]string) {
	err := r.c.Set(&cache.Item{
		Key:   fmt.Sprintf("username-%d", id),
		Value: metadata,
	})
	if err != nil {
		l.Warn("failed to update redis cache with username", zap.Error(err))
	}
}
