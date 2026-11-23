
class Plugin:

    # Default plugin name
    name = "Unknown"

    # Default computational cost
    cost = 1

    # Check whether the plugin supports the input
    def detect(self, state):

        raise NotImplementedError


    # Perform the plugin operation
    def apply(self, state):

        raise NotImplementedError


    # Explain the operation
    def explain(self, params=None):

        return "Plugin operation completed."
