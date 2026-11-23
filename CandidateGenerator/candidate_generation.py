
# Import our three plugins

from plugins.base64_plugin import Base64Plugin
from plugins.hex_plugin import HexPlugin
from plugins.binary_plugin import BinaryPlugin
from plugins.caesar_plugin import create_caesar_plugins

class CandidateGenerator:

    # Create the candidate generator

    def __init__(self, threshold=0.50, plugins=None):

        self.threshold = threshold

        # Register available plugins

        if plugins is None:

            self.plugins = [

                Base64Plugin(),

                HexPlugin(),

                BinaryPlugin()

            ]
            self.plugins.extend(create_caesar_plugins())

        else:

            self.plugins = plugins


    # Generate possible candidates

    def generate(self, state):

        candidates = []

        # Ask every plugin to check the input

        for plugin in self.plugins:

            confidence = plugin.detect(state)

            # Keep plugins that meet the threshold

            if confidence >= self.threshold:

                candidate = {

                    "name": plugin.name,

                    "confidence": confidence,

                    "cost": plugin.cost,

                    "plugin": plugin

                }

                candidates.append(candidate)


        # Try cheaper plugins first

        candidates.sort(key=lambda item: item["cost"])


        # Return selected candidates

        return candidates
