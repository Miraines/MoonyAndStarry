package http

import (
	middleware2 "github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/grpc/middleware"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestHTTPRateLimitPerIP_Basic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware2.NewHTTPRateLimitPerIP(1, 1, 100, time.Hour))
	r.GET("/", func(c *gin.Context) { c.String(200, "ok") })

	req := func(addr string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.RemoteAddr = addr
		r.HandleContext(c)
		return w
	}

	// 1-й запрос
	if w := req("1.2.3.4:12345"); w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	// 2-й — сразу 429
	if w := req("1.2.3.4:12345"); w.Code != 429 {
		t.Fatalf("want 429, got %d", w.Code)
	}
}

func TestHTTPRateLimitPerIP_DifferentHosts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware2.NewHTTPRateLimitPerIP(1, 1, 100, time.Hour))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(w1)
	c1.Request = httptest.NewRequest("GET", "/", nil)
	c1.Request.RemoteAddr = "10.0.0.1:1111"
	r.HandleContext(c1)
	if w1.Code != 200 {
		t.Fatalf("host A first request must pass, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest("GET", "/", nil)
	c2.Request.RemoteAddr = "10.0.0.2:2222"
	r.HandleContext(c2)
	if w2.Code != 200 {
		t.Fatalf("host B first request must pass independently, got %d", w2.Code)
	}
}

func TestHTTPRateLimitPerIP_TTL_Evicts(t *testing.T) {
	ttl := 10 * time.Millisecond
	r := gin.New()
	r.Use(middleware2.NewHTTPRateLimitPerIP(1, 1, 10, ttl))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	req := func() int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.RemoteAddr = "127.0.0.1:5555"
		r.HandleContext(c)
		return w.Code
	}

	if code := req(); code != 200 {
		t.Fatalf("first req want 200 got %d", code)
	}
	if code := req(); code != 429 {
		t.Fatalf("second immediate req want 429 got %d", code)
	}
	time.Sleep(ttl + 5*time.Millisecond)
	if code := req(); code != 200 {
		t.Fatalf("after TTL want 200 got %d", code)
	}
}
