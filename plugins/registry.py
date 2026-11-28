
# Import encoding plugins
from plugins.base64_plugin import Base64Plugin
from plugins.hex_plugin import HexPlugin
from plugins.binary_plugin import BinaryPlugin
from plugins.base32_plugin import Base32Plugin
from plugins.extra_encoding_plugins import (
    Base58Plugin, Base85Plugin, OctalPlugin, DecimalPlugin,
    URLPlugin, HTMLEntityPlugin, MorsePlugin
)

# Import classical cipher plugins
from plugins.atbash_plugin import AtbashPlugin
from plugins.caesar_plugin import create_caesar_plugins
from plugins.affine_plugin import create_affine_plugins

# Import automatic attack plugins
from plugins.vigenere_attack_plugin import VigenereAttackPlugin
from plugins.xor_attack_plugin import XorAttackPlugin
from plugins.substitution_attack_plugin import SubstitutionAttackPlugin


# Create all default plugins
def create_default_plugins():

    plugins = [

        # Encoding
        Base64Plugin(),
        HexPlugin(),
        BinaryPlugin(),
        Base32Plugin(),
        Base58Plugin(),
        Base85Plugin(),
        OctalPlugin(),
        DecimalPlugin(),
        URLPlugin(),
        HTMLEntityPlugin(),
        MorsePlugin(),

        # Classical ciphers
        AtbashPlugin(),

        # Automatic attacks
        VigenereAttackPlugin(),
        XorAttackPlugin(),
        SubstitutionAttackPlugin()

    ]

    # Add all Caesar candidates
    plugins.extend(create_caesar_plugins())

    # Add all Affine candidates
    plugins.extend(create_affine_plugins())

    return plugins
