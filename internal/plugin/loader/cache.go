// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"go.etcd.io/bbolt"
)

// Cache dosya mtime+sha256 anahtarlı metadata cache'idir (A-12).
// Backend: bbolt (saf Go, CGO'suz). Warm-keşif bütçesi ≤150ms buradan ölçülür.
type Cache struct {
	db *bbolt.DB
}

// OpenCache bbolt dosyasını açar (yoksa oluşturur).
func OpenCache(path string) (*Cache, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("cache open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte("plugins"))
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cache bucket: %w", err)
	}
	return &Cache{db: db}, nil
}

// Close kapatır.
func (c *Cache) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Key path + mtime_ns + api_version'dan türetilir.
func CacheKey(path string, mtime time.Time, apiVersion string) string {
	h := sha256.New()
	h.Write([]byte(path + "\x00" + mtime.UTC().Format(time.RFC3339Nano) + "\x00" + apiVersion))
	return hex.EncodeToString(h.Sum(nil))
}

// FileKey dosyanın stat'ından anahtar üretir.
func FileKey(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cache stat %s: %w", path, err)
	}
	return CacheKey(path, st.ModTime(), "1.0"), nil
}

// Get ham metadata blob'unu döner (yoksa nil).
func (c *Cache) Get(key string) ([]byte, error) {
	var out []byte
	if err := c.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("plugins"))
		v := b.Get([]byte(key))
		if v != nil {
			out = append([]byte{}, v...)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("cache get: %w", err)
	}
	return out, nil
}

// Put blob yazar.
func (c *Cache) Put(key string, value []byte) error {
	if err := c.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("plugins")).Put([]byte(key), value)
	}); err != nil {
		return fmt.Errorf("cache put: %w", err)
	}
	return nil
}
