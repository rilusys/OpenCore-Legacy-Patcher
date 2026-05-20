"""
security.py: Class for handling macOS Security Patches, invocation from build.py
"""

import logging
import binascii

from . import support

from .. import constants

from ..support import utilities
from ..detections import device_probe

from ..datasets import (
    model_array,
    smbios_data,
    os_data,
    security_fallback,
)


class BuildSecurity:
    """
    Build Library for Security Patch Support

    Invoke from build.py
    """

    def __init__(self, model: str, global_constants: constants.Constants, config: dict) -> None:
        self.model: str = model
        self.config: dict = config
        self.constants: constants.Constants = global_constants
        self.computer: device_probe.Computer = self.constants.computer

        self._build()

    def _is_t2_mac(self) -> bool:
        return self.model in model_array.T2Macs

    def _apply_t2_security_fallback(self) -> None:
        fallback = security_fallback.get_security_fallback(self.model)
        apple_nvram = "7C436110-AB2A-4BBB-A880-FE41995C9F82"

        for key, value in fallback.items():
            if key == "csr-active-config":
                if isinstance(value, str):
                    value = binascii.unhexlify(value)
                self.config["NVRAM"]["Add"][apple_nvram][key] = value
            elif key == "boot-args":
                if isinstance(value, list):
                    value = " ".join(value)
                self.config["NVRAM"]["Add"][apple_nvram]["boot-args"] += f" {value}"
            else:
                parts = key.split(".")
                target = self.config
                for part in parts[:-1]:
                    target = target.setdefault(part, {})
                target[parts[-1]] = value

    def _build(self) -> None:
        """
        Kick off Security Build Process
        """

        is_t2 = self._is_t2_mac()

        if self.constants.sip_status is False or self.constants.custom_sip_value:
            logging.info("- Adding ipc_control_port_options=0 to boot-args")
            self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " ipc_control_port_options=0"
            if self.constants.wxpython_variant is True:
                support.BuildSupport(self.model, self.constants, self.config).enable_kext("AutoPkgInstaller.kext", self.constants.autopkg_version, self.constants.autopkg_path)
            if self.constants.custom_sip_value:
                logging.info(f"- Setting SIP value to: {self.constants.custom_sip_value}")
                self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["csr-active-config"] = utilities.string_to_hex(self.constants.custom_sip_value.lstrip("0x"))
            elif self.constants.sip_status is False:
                logging.info("- Set SIP to allow Root Volume patching")
                self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["csr-active-config"] = binascii.unhexlify("03080000")

            logging.info("- Allowing FileVault on Root Patched systems")
            support.BuildSupport(self.model, self.constants, self.config).get_item_by_kv(self.config["Kernel"]["Patch"], "Comment", "Force FileVault on Broken Seal")["Enabled"] = True
            self.config["NVRAM"]["Add"]["4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102"]["OCLP-Settings"] += " -allow_fv"
            logging.info("- Enabling KC UUID mismatch patch")
            self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " -nokcmismatchpanic"
            support.BuildSupport(self.model, self.constants, self.config).enable_kext("RSRHelper.kext", self.constants.rsrhelper_version, self.constants.rsrhelper_path)

        if self.constants.disable_cs_lv is True:
            if self.constants.disable_amfi is True and not is_t2:
                # T2 Macs use AMFIPass instead of amfi=0x80
                logging.info("- Disabling AMFI")
                self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " amfi=0x80"
            else:
                logging.info("- Disabling Library Validation")
            support.BuildSupport(self.model, self.constants, self.config).get_item_by_kv(self.config["Kernel"]["Patch"], "Comment", "Disable Library Validation Enforcement")["Enabled"] = True
            support.BuildSupport(self.model, self.constants, self.config).get_item_by_kv(self.config["Kernel"]["Patch"], "Comment", "Disable _csr_check() in _vnode_check_signature")["Enabled"] = True
            self.config["NVRAM"]["Add"]["4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102"]["OCLP-Settings"] += " -allow_amfi"
            support.BuildSupport(self.model, self.constants, self.config).enable_kext("CSLVFixup.kext", self.constants.cslvfixup_version, self.constants.cslvfixup_path)

        if self.constants.secure_status is False:
            logging.info("- Disabling SecureBootModel")
            self.config["Misc"]["Security"]["SecureBootModel"] = "Disabled"

        if is_t2:
            self.config["Kernel"]["Quirks"]["ForceSecureBootScheme"] = True
            logging.info("- Enabling ForceSecureBootScheme for T2 Mac")

        if is_t2 or smbios_data.smbios_dictionary[self.model]["Max OS Supported"] < os_data.os_data.sonoma:
            logging.info("- Enabling AMFIPass")
            support.BuildSupport(self.model, self.constants, self.config).enable_kext("AMFIPass.kext", self.constants.amfipass_version, self.constants.amfipass_path)

        if is_t2:
            self._apply_t2_security_fallback()
