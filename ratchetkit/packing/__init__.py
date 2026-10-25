"""Wire packing: constructor IDs.

Object dispatch lives in :mod:`ratchetkit.packing.registry` so this package
can be imported while those types are still loading.
"""

from ratchetkit.packing.constructor import (
    CONSTRUCTOR_SIZE,
    ConstructorId,
    expect_constructor,
    pack_constructor,
    read_constructor,
)

__all__ = [
    "CONSTRUCTOR_SIZE",
    "ConstructorId",
    "expect_constructor",
    "pack_constructor",
    "read_constructor",
]
