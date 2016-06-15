package main

import (
	"hash"
	"os"
	"sync"
	"time"
)

const (
	STATE_STARTING int64 = iota
	STATE_UPLOADING
	STATE_DONE
	STATE_ERROR
)

type Session struct {
	resumeable            bool
	start, last           time.Time
	name, path, errmsg    string
	state, size, received int64
	checksum              hash.Hash
}

type Sessions struct {
	items map[string]*Session
	sync.RWMutex
}

func NewSessions() *Sessions {
	return &Sessions{
		items: map[string]*Session{},
	}
}

func (this *Sessions) Set(key string, session *Session) *Session {
	this.Lock()
	this.items[key] = session
	this.Unlock()
	return session
}

func (this *Sessions) Get(key string) *Session {
	this.RLock()
	value := this.items[key]
	this.RUnlock()
	return value
}

func (this *Sessions) Keys() []string {
	var keys []string
	this.RLock()
	for key, _ := range this.items {
		keys = append(keys, key)
	}
	this.RUnlock()
	return keys
}

func (this *Sessions) Counts() (int, int) {
	progressive := 0
	resumeable := 0
	this.RLock()
	for _, value := range this.items {
		if value.state == STATE_UPLOADING {
			if value.resumeable {
				resumeable++
			} else {
				progressive++
			}
		}
	}
	this.RUnlock()
	return progressive, resumeable
}

func (this *Sessions) Cleanup(progressiveTimeout, resumeableTimeout, doneTimeout int64) {
	var keys []string

	now := time.Now()
	this.RLock()
	for key, value := range this.items {
		delta := int64(now.Sub(value.last))
		if value.state != STATE_DONE && value.state != STATE_ERROR {
			if !value.resumeable && delta >= (int64(time.Second)*progressiveTimeout) {
				keys = append(keys, key)
			}
			if value.resumeable && delta >= (int64(time.Second)*resumeableTimeout) {
				keys = append(keys, key)
			}
		} else {
			if delta >= (int64(time.Second) * doneTimeout) {
				keys = append(keys, key)
			}
		}
	}
	this.RUnlock()
	this.Lock()
	for _, key := range keys {
		os.Remove(this.items[key].path)
		delete(this.items, key)
	}
	this.Unlock()
}
