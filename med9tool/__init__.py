"""MED9Tool — MED9.1/MED9.5 ECU editor for MPC5xx platforms."""
__version__ = "0.1.2"

from .fr_database import (  # noqa: F401
    FRParam, ALL_PARAMS, BGVMAX_PARAMS, NMAXMD_PARAMS,
    get_param, raw_to_phys, phys_to_raw,
    SPEED_REMOVE_RAW, SPEED_REMOVE_PHYS,
)
