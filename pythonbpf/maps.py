class HashMap:
    def __init__(self, key_type, value_type, max_entries):
        self.key_type = key_type
        self.value_type = value_type
        self.max_entries = max_entries
        self.entries = {}
        
    # add other supported map functions here
