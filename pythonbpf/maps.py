class HashMap:
    def __init__(self, key, value, max_entries):
        self.key = key
        self.value = value
        self.max_entries = max_entries
        self.entries = {}

    def lookup(self, key):
        if key in self.entries:
            return self.entries[key]
        else:
            return None

    def delete(self, key):
        if key in self.entries:
            del self.entries[key]
        else:
            raise KeyError(f"Key {key} not found in map")

    # TODO: define the flags that can be added
    def update(self, key, value, flags=None):
        if key in self.entries:
            self.entries[key] = value
        else:
            raise KeyError(f"Key {key} not found in map")


class PerfEventArray:
    def __init__(self, key_size, value_size):
        self.key_type = key_size
        self.value_type = value_size
        self.entries = {}
