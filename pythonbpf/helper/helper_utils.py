class HelperHandlerRegistry:
    """Registry for BPF helpers"""
    _handlers = {}

    @classmethod
    def register(cls, helper_name):
        """Decorator to register a handler function for a helper"""
        def decorator(func):
            cls._handlers[helper_name] = func
            return func
        return decorator

    @classmethod
    def get_handler(cls, helper_name):
        """Get the handler function for a helper"""
        return cls._handlers.get(helper_name)
