import threading

class CacheService:
    """
    Enterprise-grade Thread-Safe In-Memory Cache.
    Designed for future horizontal scaling with Redis.
    """
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def get(self, key):
        """Retrieve item from cache"""
        with self._lock:
            return self._cache.get(key)

    def set(self, key, value):
        """Store item in cache"""
        with self._lock:
            self._cache[key] = value

    def clear(self):
        """Wipe the cache (useful for admin/testing)"""
        with self._lock:
            self._cache.clear()

# Singleton instance for high-performance access
cache_service = CacheService()
