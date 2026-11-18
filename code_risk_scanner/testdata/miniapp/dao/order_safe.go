package dao

import (
	"context"
	"net/http"
	"sync"
	"time"
)

func Leak(ctx context.Context, ch chan int) {
	go func() {
		select {
		case ch <- 1:
		case <-ctx.Done():
			return
		}
	}()
}

func WriteMap() {
	var mu sync.Mutex
	m := make(map[string]int)
	go func() {
		mu.Lock()
		m["a"] = 1
		mu.Unlock()
	}()
}

func Fetch(urls []string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	for _, u := range urls {
		func() {
			resp, err := client.Get(u)
			if err != nil {
				return
			}
			defer resp.Body.Close()
		}()
	}
	return nil
}
