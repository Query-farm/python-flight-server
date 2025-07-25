from typing import Literal

import msgpack
from pyarrow import flight

RecognizedConstraintTypes = Literal[
    "ConstraintException", "PermissionException", "InvalidInputException"
]


class ExceptionWithExtraInfo(flight.FlightServerError):
    """Custom exception class with extra information serialized as msgpack.

    Parameters
    ----------
    exception_type : str
        The type of the exception.
    message : str
        The error message to be displayed.
    """

    def __init__(self, exception_type: RecognizedConstraintTypes, message: str):
        packed_extra = msgpack.packb(
            {
                "exception_type": exception_type,
                "message": message,
            }
        )

        super().__init__(message, extra_info=packed_extra)


class PermissionException(ExceptionWithExtraInfo):
    """
    Exception raised for permission-related errors.

    Parameters
    ----------
    message : str
        The error message to be displayed.
    """

    def __init__(self, message: str):
        super().__init__("PermissionException", message)


class InvalidInputException(ExceptionWithExtraInfo):
    """
    Exception raised for invalid input errors.

    Parameters
    ----------
    message : str
        The error message to be displayed.
    """

    def __init__(self, message: str):
        super().__init__("InvalidInputException", message)


class ConstraintException(ExceptionWithExtraInfo):
    """
    Exception raised for constraint violations.

    Parameters
    ----------
    column_name : str
        The name of the column that caused the constraint violation.
    duplicated_value : str
        The value that caused the constraint violation.
    """

    def __init__(self, column_name: str, duplicated_value: str):
        super().__init__(
            "ConstraintException",
            f"""Duplicate key "{column_name}: {duplicated_value}" violates primary key constraint.""",
        )
