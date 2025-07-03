package middleware

import (
	"github.com/gin-gonic/gin"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
	"net"
	"time"
)

// NewHTTPRateLimitPerIP ограничивает RPS для Gin-ручек c LRU-кэшем IP.
func NewHTTPRateLimitPerIP(
	limit, burst, cacheSize int,
	ttl time.Duration,
) gin.HandlerFunc {

	visitors, _ := lru.New[string, *visitor](cacheSize)

	// Периодическая очистка неактивных IP.
	go func() {
		ticker := time.NewTicker(ttl)
		for range ticker.C {
			for _, key := range visitors.Keys() {
				if v, ok := visitors.Peek(key); ok && time.Since(v.last) > ttl {
					visitors.Remove(key)
				}
			}
		}
	}()

	return func(c *gin.Context) {
		host, _, _ := net.SplitHostPort(c.Request.RemoteAddr)

		v, ok := visitors.Get(host)
		if !ok {
			v = &visitor{
				limiter: rate.NewLimiter(rate.Limit(limit), burst),
			}
			visitors.Add(host, v)
		}
		v.last = time.Now()

		if !v.limiter.Allow() {
			c.AbortWithStatusJSON(429, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}
