package middleware

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

func RequestLogger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// но без токенов/паролей – фильтруем всё, что выглядит чувствительным.
		scrub := func(h http.Header) http.Header {
			clone := h.Clone()
			for k := range clone {
				if strings.Contains(strings.ToLower(k), "authorization") ||
					strings.Contains(strings.ToLower(k), "cookie") {
					clone[k] = []string{"[redacted]"}
				}
			}
			return clone
		}

		reqHeaders, _ := json.Marshal(scrub(c.Request.Header))
		log.Debug("↘︎ incoming request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("origin", c.GetHeader("Origin")),
			zap.ByteString("hdr", reqHeaders),
		)

		ts := time.Now()
		c.Next()

		latency := time.Since(ts)
		respStatus := c.Writer.Status()

		// Если CORS (или другой middleware) прервал работу
		if c.IsAborted() {
			log.Warn("↗︎ aborted",
				zap.Int("status", respStatus),
				zap.Duration("latency", latency),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
			)
			return
		}

		// Ошибки, которые handler сохранил в c.Errors
		if len(c.Errors) > 0 {
			for _, e := range c.Errors {
				log.Error("handler error",
					zap.Int("status", respStatus),
					zap.Error(e),
					zap.String("path", c.Request.URL.Path),
				)
			}
		}

		log.Info("↗︎ completed",
			zap.Int("status", respStatus),
			zap.Duration("latency", latency),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
		)
	}
}
