class HashMap:
    def __init__(self, key_type, value_type, max_entries):
        self.key_type = key_type
        self.value_type = value_type
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
            
    def update(self, key, value):
        if key in self.entries:
            self.entries[key] = value
        else:
            raise KeyError(f"Key {key} not found in map")
