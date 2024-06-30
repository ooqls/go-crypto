package usercachev1

import "sync"

var m sync.Mutex = sync.Mutex{}
var c UserMetadataCache

func Get() UserMetadataCache {
	m.Lock()
	defer m.Unlock()

	return c
}

func Set(newC UserMetadataCache) {
	m.Lock()
	defer m.Unlock()

	c = newC
}
