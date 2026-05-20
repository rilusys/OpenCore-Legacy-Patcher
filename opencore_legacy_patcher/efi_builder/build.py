"""
build.py: Class for generating OpenCore Configurations tailored for Macs
"""

import copy
import pickle
import shutil
import logging
import zipfile
import plistlib

from pathlib import Path
from datetime import date

from .. import constants

from ..support import utilities
from ..datasets import model_array

from .networking import (
    wired,
    wireless
)
from . import (
    bluetooth,
    firmware,
    graphics_audio,
    support,
    storage,
    smbios,
    security,
    misc,
    t2smbiossecurity,
)


def rmtree_handler(func, path, exc_info) -> None:
    if exc_info[0] == FileNotFoundError:
        return
    raise  # pylint: disable=misplaced-bare-raise


class BuildOpenCore:
    """
    Core Build Library for generating and validating OpenCore EFI Configurations
    compatible with genuine Macs
    """

    def __init__(self, model: str, global_constants: constants.Constants) -> None:
        self.model: str = model
        self.config: dict = None
        self.constants: constants.Constants = global_constants

        self._build_opencore()


    def _remove_conflicting_t2_ssdt(self) -> None:
        """
        Removes SSDT-T2-Fake.aml if a T2 Mac is detected, to prevent conflicts
        with T2-specific kernel patches and boot-args.
        """
        ssdt_path = self.constants.acpi_path / "SSDT-T2-Fake.aml"
        if ssdt_path.exists():
            logging.warning(f"Removing SSDT-T2-Fake.aml for T2 Mac ({self.model})")
            ssdt_path.unlink()

    def _build_efi(self) -> None:
        """
        Build EFI folder
        """

        utilities.cls()
        logging.info(f"Building Configuration {'for external' if self.constants.custom_model else 'on model'}: {self.model}")

        self._generate_base()
        self._set_revision()

        # Set Lilu and co.
        support.BuildSupport(self.model, self.constants, self.config).enable_kext("Lilu.kext", self.constants.lilu_version, self.constants.lilu_path)
        self.config["Kernel"]["Quirks"]["DisableLinkeditJettison"] = True

        is_t2 = self.model in model_array.T2Macs

        # Intel UHD 630 VMM Stall Fix (2018-2020 T2 Models)
        _T2_UHD630_MODELS = [
            "MacBookPro15,1", "MacBookPro15,2", "MacBookPro15,3", "MacBookPro15,4",
            "MacBookPro16,1", "MacBookPro16,2", "MacBookPro16,3", "MacBookPro16,4",
            "Macmini8,1", "iMac19,1", "iMac19,2", "iMac20,1", "iMac20,2",
        ]
        if self.model in _T2_UHD630_MODELS:
            logging.info(f"- Disabling VMM CPUID for {self.model} to prevent UHD 630 driver stall")
            self.constants.set_vmm_cpuid = False

        if is_t2:
            self._remove_conflicting_t2_ssdt()
            t2smbiossecurity.finalize_t2_tahoe(self.constants.plist_path)
            logging.info("- Adding T2-specific boot args")
            self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " -ibtcompatbeta -amfipassbeta"
            self.config["Kernel"]["Quirks"]["DisableIoMapper"] = True

        # macOS Sequoia/Tahoe support for Lilu plugins
        # T2 Macs: use -liluforce to avoid corecrypto FIPS POST panic caused by -lilubetaall
        if is_t2:
            self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " -liluforce"
        else:
            self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " -lilubetaall"

        # Call support functions
        for function in [
            firmware.BuildFirmware,
            wired.BuildWiredNetworking,
            wireless.BuildWirelessNetworking,
            graphics_audio.BuildGraphicsAudio,
            bluetooth.BuildBluetooth,
            storage.BuildStorage,
            smbios.BuildSMBIOS,
            security.BuildSecurity,
            misc.BuildMiscellaneous
        ]:
            function(self.model, self.constants, self.config)

        # Work-around ocvalidate
        if self.constants.validate is False:
            logging.info("- Adding bootmgfw.efi BlessOverride")
            self.config["Misc"]["BlessOverride"] += ["\\EFI\\Microsoft\\Boot\\bootmgfw.efi"]


    def _generate_base(self) -> None:
        """
        Generate OpenCore base folder and config
        """

        if not Path(self.constants.build_path).exists():
            logging.info("Creating build folder")
            Path(self.constants.build_path).mkdir()
        else:
            logging.info("Build folder already present, skipping")

        if Path(self.constants.opencore_zip_copied).exists():
            logging.info("Deleting old copy of OpenCore zip")
            Path(self.constants.opencore_zip_copied).unlink()
        if Path(self.constants.opencore_release_folder).exists():
            logging.info("Deleting old copy of OpenCore folder")
            shutil.rmtree(self.constants.opencore_release_folder, onerror=rmtree_handler, ignore_errors=True)

        logging.info("")
        logging.info(f"- Adding OpenCore v{self.constants.opencore_version} {'DEBUG' if self.constants.opencore_debug is True else 'RELEASE'}")
        shutil.copy(self.constants.opencore_zip_source, self.constants.build_path)
        zipfile.ZipFile(self.constants.opencore_zip_copied).extractall(self.constants.build_path)

        # Setup config.plist for editing
        logging.info("- Adding config.plist for OpenCore")
        shutil.copy(self.constants.plist_template, self.constants.oc_folder)
        self.config = plistlib.load(Path(self.constants.plist_path).open("rb"))


    def _set_revision(self) -> None:
        """
        Set revision information in config.plist
        """

        self.config["#Revision"]["Build-Version"] = f"{self.constants.patcher_version} - {date.today()}"
        if not self.constants.custom_model:
            self.config["#Revision"]["Build-Type"] = "OpenCore Built on Target Machine"
            computer_copy = copy.copy(self.constants.computer)
            computer_copy.ioregistry = None
            self.config["#Revision"]["Hardware-Probe"] = pickle.dumps(computer_copy)
        else:
            self.config["#Revision"]["Build-Type"] = "OpenCore Built for External Machine"
        self.config["#Revision"]["OpenCore-Version"] = f"{self.constants.opencore_version} - {'DEBUG' if self.constants.opencore_debug is True else 'RELEASE'}"
        self.config["#Revision"]["Original-Model"] = self.model
        self.config["NVRAM"]["Add"]["4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102"]["OCLP-Version"] = f"{self.constants.patcher_version}"
        self.config["NVRAM"]["Add"]["4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102"]["OCLP-Model"] = self.model


    def _save_config(self) -> None:
        """
        Save config.plist to disk
        """

        plistlib.dump(self.config, Path(self.constants.plist_path).open("wb"), sort_keys=True)


    def _build_opencore(self) -> None:
        """
        Kick off the build process

        This is the main function:
        - Generates the OpenCore configuration
        - Cleans working directory
        - Signs files
        - Validates generated EFI
        """

        # Generate OpenCore Configuration
        self._build_efi()
        if self.constants.allow_oc_everywhere is False or self.constants.allow_native_spoofs is True or (self.constants.custom_serial_number != "" and self.constants.custom_board_serial_number != ""):
            smbios.BuildSMBIOS(self.model, self.constants, self.config).set_smbios()
        support.BuildSupport(self.model, self.constants, self.config).cleanup()
        self._save_config()

        # Post-build handling
        support.BuildSupport(self.model, self.constants, self.config).sign_files()
        support.BuildSupport(self.model, self.constants, self.config).validate_pathing()

        logging.info("")
        logging.info(f"Your OpenCore EFI for {self.model} has been built at:")
        logging.info(f"    {self.constants.opencore_release_folder}")
        logging.info("")
