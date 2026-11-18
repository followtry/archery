package dao

import (
	"database/sql"
	"net/http"
)

func Leak(ch chan int) {
	go func() {
		ch <- 1
	}()
}

func WriteMap() {
	m := make(map[string]int)
	go func() {
		m["a"] = 1
	}()
}

func Fetch(urls []string) {
	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		_ = resp
		_ = err
	}
}

func SaveAll(db *sql.DB, ids []int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, id := range ids {
		_, err = tx.Exec("update order_tab set status = 1 where user_id = ?", id)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
