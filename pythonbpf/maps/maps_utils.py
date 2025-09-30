class MapProcessorRegistry:
    """Registry for map processor functions"""

    _processors = {}

    @classmethod
    def register(cls, map_type_name):
        """Decorator to register a processor function for a map type"""

        def decorator(func):
            cls._processors[map_type_name] = func
            return func

        return decorator

    @classmethod
    def get_processor(cls, map_type_name):
        """Get the processor function for a map type"""
        return cls._processors.get(map_type_name)
