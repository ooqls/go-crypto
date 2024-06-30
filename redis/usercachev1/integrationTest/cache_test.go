package integrationTest

import (
	"context"
	"testing"
	"time"

	"github.com/braumsmilk/go-token/redis/usercachev1"
	"github.com/braumsmilk/go-token/testutils"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	timeout := time.Second * 30
	c := testutils.InitRedis()
	defer c.Stop(context.Background(), &timeout)

	m.Run()
}

func TestUserCache(t *testing.T) {
	ucache := usercachev1.NewRedisCache()
	ucache.AddUser(1, map[string]string{"name": "user"})

	meta := ucache.GetUser(1)
	assert.Equalf(t, "user", meta["name"], "should get the same name for userid")
}
