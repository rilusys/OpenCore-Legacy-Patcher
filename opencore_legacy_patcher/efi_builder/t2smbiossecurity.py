"""
t2smbiossecurity.py: T2-specific SMBIOS and Security configuration for OpenCore configs.

Sets Booter and Security quirks required for T2 Macs to boot macOS
through OpenCorePkg without SEP-related panics.
"""

import plistlib
import logging


def finalize_t2_tahoe(path):
    """
    Apply T2 Tahoe Booter and Security patches to config.plist.

    Ensures dictionary keys exist before writing to prevent plist corruption.
    Sets SecureBootModel to Disabled and ensures Booter quirks are correct
    for T2 Macs.
    """
    logging.info(f"Applying T2 Tahoe Booter and Security patches to: {path}")

    try:
        with open(path, 'rb') as f:
            config = plistlib.load(f)

        booter = config.setdefault('Booter', {})
        quirks = booter.setdefault('Quirks', {})

        quirks.update({
            'RebuildAppleMemoryMap': False,
            'EnableWriteUnprotector': False,
            'SyncRuntimePermissions': False,
            'DevirtualiseMmio': False,
        })

        platform_info = config.setdefault('PlatformInfo', {})
        platform_info['UpdateSMBIOSMode'] = 'Custom'

        misc = config.setdefault('Misc', {})
        security = misc.setdefault('Security', {})
        security['SecureBootModel'] = 'Disabled'

        kernel = config.setdefault('Kernel', {})
        kernel_quirks = kernel.setdefault('Quirks', {})
        if 'DisableIoMapper' not in kernel_quirks:
            kernel_quirks['DisableIoMapper'] = True

        with open(path, 'wb') as f:
            plistlib.dump(config, f, sort_keys=True)

        logging.info("T2 Tahoe Booter/Security patches applied successfully")

    except Exception as e:
        logging.error(f"Failed to apply T2 Tahoe patches: {e}")
        raise
