package dao

import "net/http"

func TestFetch(t *testing.T) {
	http.Get("http://example.com")
}
