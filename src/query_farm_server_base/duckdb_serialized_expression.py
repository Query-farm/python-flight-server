import base64
import codecs
import math
import uuid
from datetime import date, timedelta, time
from decimal import Decimal
from typing import Any
from datetime import datetime, timezone


def _quote_string(value: str) -> str:
    assert isinstance(value, str)
    return f"'{value}'"


def decode_base64_value(value: Any) -> bytes:
    assert "base64" in value
    return base64.b64decode(value["base64"])


def decode_bitstring(data: bytes) -> str:
    if not data or len(data) < 2:
        return ""

    padding_bits = data[0]
    bit_data = data[1:]

    # Convert all bytes to bits
    bits = "".join(f"{byte:08b}" for byte in bit_data)

    # Remove the padding bits from the end
    if padding_bits:
        bits = bits[padding_bits:]

    return bits


def interpret_time(value: int) -> str:
    t = timedelta(milliseconds=value)
    hours, remainder = divmod(t.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    result = time(hours, minutes, seconds, microsecond=t.microseconds)
    return result.strftime("%H:%M:%S.%f")


def interpret_real(value: Any) -> str:
    if math.isinf(value):
        if value > 0:
            return "'infinity'"
        return "'-infinity'"
    elif math.isnan(value):
        return "'nan'"
    return value


def interpret_timestamp_ms(value: int) -> str:
    dt = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Trim to milliseconds


def decode_uuid(value: dict[str, int]) -> str:
    assert "upper" in value and "lower" in value, "Invalid GUID format"

    # Handle the two's complement for the signed upper 64 bits
    upper = value["upper"] & ((1 << 64) - 1)  # Convert to unsigned if needed
    lower = value["lower"]

    # Combine into 128-bit integer
    combined = (upper << 64) | lower

    # Convert to 16 bytes (big-endian)
    bytes_ = combined.to_bytes(16, byteorder="big")

    # Create UUID from bytes
    u = uuid.UUID(bytes=bytes_)

    return str(u)


def decode_date(days: int) -> str:
    if days == -2147483647:
        return "'-infinity'"
    elif days == 2147483647:
        return "'infinity'"
    formatted_date = (date(1970, 1, 1) + timedelta(days=days)).isoformat()
    return f"'{formatted_date}'"


def interpret_decimal(value: dict[str, Any]) -> Decimal:
    type_info = value["type"]["type_info"]
    scale = type_info["scale"]
    v = value["value"]

    if isinstance(v, dict) and "upper" in v and "lower" in v:
        # Combine upper and lower into a 128-bit signed integer
        upper = v["upper"]
        lower = v["lower"]

        # Reconstruct full integer (assuming 64-bit halves)
        combined = (upper << 64) | lower

        # Convert from unsigned to signed (two's complement if necessary)
        if upper & (1 << 63):
            combined -= 1 << 128

        decimal_value = Decimal(combined)
    elif isinstance(v, int):
        # Assume it's a simple int (64-bit)
        decimal_value = Decimal(v)
    else:
        raise ValueError("Unsupported decimal value format")

    return decimal_value / Decimal(10) ** scale


def varint_get_byte_array(blob: bytes) -> tuple[list[int], bool]:
    if len(blob) < 4:
        raise ValueError("Invalid blob size.")

    # Determine if the number is negative
    is_negative = (blob[0] & 0x80) == 0

    # Extract byte array starting from the 4th byte
    if is_negative:
        byte_array = [~b & 0xFF for b in blob[3:]]  # Apply bitwise NOT and mask to 8 bits
    else:
        byte_array = list(blob[3:])

    return byte_array, is_negative


def varint_to_varchar(blob: bytes) -> str:
    decimal_string = ""
    byte_array, is_negative = varint_get_byte_array(blob)
    digits: list[int] = []

    # Constants matching your C++ code (update if needed)
    DIGIT_BYTES = 4  # Assuming 4 bytes per digit (like a uint32_t)
    DIGIT_BITS = 32
    DECIMAL_BASE = 1000000000  # Typically 10^9 for efficient base conversion
    DECIMAL_SHIFT = 9  # Number of decimal digits in DECIMAL_BASE

    # Pad the byte array so we can process in DIGIT_BYTES chunks without conditionals
    padding_size = (-len(byte_array)) & (DIGIT_BYTES - 1)
    byte_array = [0] * padding_size + byte_array

    for i in range(0, len(byte_array), DIGIT_BYTES):
        hi = 0
        for j in range(DIGIT_BYTES):
            hi |= byte_array[i + j] << (8 * (DIGIT_BYTES - j - 1))

        for j in range(len(digits)):
            tmp = (digits[j] << DIGIT_BITS) | hi
            hi = tmp // DECIMAL_BASE
            digits[j] = tmp - DECIMAL_BASE * hi

        while hi:
            digits.append(hi % DECIMAL_BASE)
            hi //= DECIMAL_BASE

    if not digits:
        digits.append(0)

    for i in range(len(digits) - 1):
        remain = digits[i]
        for _ in range(DECIMAL_SHIFT):
            decimal_string += str(remain % 10)
            remain //= 10

    remain = digits[-1]
    while remain != 0:
        decimal_string += str(remain % 10)
        remain //= 10

    if is_negative:
        decimal_string += "-"

    # Reverse the string to get the correct number
    decimal_string = decimal_string[::-1]
    return decimal_string if decimal_string else "0"


comparison_type_to_operator: dict[str, str] = {
    "COMPARE_EQUAL": "=",
    "COMPARE_NOTEQUAL": "!=",
    "COMPARE_LESSTHAN": "<",
    "COMPARE_GREATERTHAN": ">",
    "COMPARE_LESSTHANOREQUALTO": "<=",
    "COMPARE_GREATERTHANOREQUALTO": ">=",
    "COMPARE_DISTINCT_FROM": "IS DISTINCT FROM",
    "COMPARE_NOT_DISTINCT_FROM": "IS NOT DISTINCT FROM",
}


def comparison_type_to_string_(comparison_type: str) -> str:
    result = comparison_type_to_operator.get(comparison_type)
    if result is not None:
        return result
    raise NotImplementedError(f"Comparison type {comparison_type} is not supported")


non_parameterized_duckdb_types = {
    "BIGINT",
    "BIT",
    "BLOB",
    "BOOLEAN",
    "DATE",
    "DOUBLE",
    "FLOAT",
    "HUGEINT",
    "INTEGER",
    "INTERVAL",
    "NULL",
    "SMALLINT",
    "TIME",
    "TIME WITH TIME ZONE",
    "TIMESTAMP_MS",
    "TIMESTAMP_NS",
    "TIMESTAMP_S",
    "TINYINT",
    "UBIGINT",
    "UHUGEINT",
    "UINTEGER",
    "USMALLINT",
    "UTINYINT",
    "UUID",
    "VARCHAR",
    "VARINT",
}


def _type_to_sql_type(type: dict[str, Any]) -> str:
    """
    Convert the serialied type information into SQL that can be
    used to recreate the type.
    """
    if type["id"] == "STRUCT":
        return (
            "STRUCT("
            + ",".join(
                [
                    f'"{child["first"]}" {_type_to_sql_type(child["second"])}'
                    for child in type["type_info"]["child_types"]
                ]
            )
            + ")"
        )
    elif type["id"] in non_parameterized_duckdb_types:
        return type["id"]
    elif type["id"] == "DECIMAL":
        return f"DECIMAL({type['type_info']['width']}, {type['type_info']['scale']})"
    elif type["id"] == "LIST":
        return _type_to_sql_type(type["type_info"]["child_type"]) + "[]"
    else:
        raise NotImplementedError(f"Type {type['id']} is not supported")


def expression_to_string(
    *, expression: dict[str, Any], bound_column_names: list[str], bound_column_types: dict[str, Any]
) -> str:
    """
    Convert a DuckDB serialized expression back into SQL, with the types of the
    columns tracked.
    """

    def e_to_s(expr: dict[str, Any]) -> str:
        return expression_to_string(
            expression=expr,
            bound_column_names=bound_column_names,
            bound_column_types=bound_column_types,
        )

    if expression["expression_class"] == "BOUND_COLUMN_REF":
        column_name = bound_column_names[expression["binding"]["column_index"]]
        bound_column_types[column_name] = expression["return_type"]
        return f'"{column_name}"'
    elif expression["expression_class"] == "BOUND_CAST":
        return (
            f"CAST({e_to_s(expression['child'])} AS {_type_to_sql_type(expression['return_type'])})"
        )
    elif expression["expression_class"] == "BOUND_CONSTANT":
        if expression["value"]["is_null"]:
            return "null"
        elif expression["value"]["type"]["id"] == "VARINT":
            varint_value = expression["value"]["value"]
            if isinstance(varint_value, str):
                varint_bytes = codecs.decode(varint_value, "unicode_escape").encode("utf-8")
            elif "base64" in varint_value:
                varint_bytes = decode_base64_value(varint_value)
            else:
                raise Exception(
                    "Varint value must be a base64 encoded string or a string with unicode escape sequences"
                )

            return varint_to_varchar(varint_bytes)
        elif expression["value"]["type"]["id"] == "UUID":
            return decode_uuid(expression["value"]["value"])
        elif expression["value"]["type"]["id"] in (
            "VARCHAR",
            "BLOB",
        ):
            return _quote_string(expression["value"]["value"])
        elif expression["value"]["type"]["id"] == "BIT":
            bit_value = expression["value"]["value"]

            if isinstance(bit_value, str):
                bitstring_bytes = codecs.decode(bit_value, "unicode_escape").encode("utf-8")
            elif "base64" in bit_value:
                bitstring_bytes = decode_base64_value(bit_value)
            else:
                raise Exception(
                    "Bit string value must be a base64 encoded string or a string with unicode escape sequences"
                )
            return decode_bitstring(bitstring_bytes)
        elif expression["value"]["type"]["id"] == "BOOLEAN":
            return "True" if expression["value"]["value"] else "False"
        elif expression["value"]["type"]["id"] == "NULL":
            return "null"
        elif expression["value"]["type"]["id"] == "DATE":
            return decode_date(expression["value"]["value"])
        elif expression["value"]["type"]["id"] == "DECIMAL":
            decimal_value = interpret_decimal(expression["value"])
            return str(decimal_value)
        elif expression["value"]["type"]["id"] in ("FLOAT", "DOUBLE"):
            return interpret_real(expression["value"]["value"])
        elif expression["value"]["type"]["id"] in (
            "BIGINT",
            "INTEGER",
            "HUGEINT",
            "TINYINT",
            "SMALLINT",
            "UBIGINT",
            "UHUGEINT",
            "UINTEGER",
            "USMALLINT",
            "UTINYINT",
        ):
            return str(expression["value"]["value"])
        elif expression["value"]["type"]["id"] == "INTERVAL":
            iv = expression["value"]["value"]
            return "INTERVAL '" + f"{iv['months']} months {iv['days']} days {iv['micros']} us" + "'"
        elif expression["value"]["type"]["id"] == "TIMESTAMP":
            return f"make_timestamp({expression['value']['value']}::bigint)"
        elif expression["value"]["type"]["id"] == "TIMESTAMP WITH TIME ZONE":
            return f"to_timestamp({expression['value']['value']}::bigint)"
        elif expression["value"]["type"]["id"] == "TIME":
            return f"TIME '{interpret_time(expression['value']['value'])}'"
        elif expression["value"]["type"]["id"] == "TIMESTAMP_S":
            return f"make_timestamp({expression['value']['value']}::bigint*1000000)"
        elif expression["value"]["type"]["id"] == "TIMESTAMP_MS":
            return f"'{interpret_timestamp_ms(expression['value']['value'])}'"
        elif expression["value"]["type"]["id"] == "TIMESTAMP_NS":
            return f"make_timestamp_ns({expression['value']['value']}::bigint)"
        #        elif expression["value"]["type"]["id"] == "TIMESTAMP WITH TIME ZONE":
        #            return f"make_timestamp({expression['value']['value']}::bigint)"
        elif expression["value"]["type"]["id"] == "LIST":
            if expression["type"] == "VALUE_CONSTANT":
                # So the children in this case aren't expressions, they are constants.
                return (
                    "["
                    + ", ".join(
                        [
                            e_to_s(
                                {
                                    "type": "VALUE_CONSTANT",
                                    "expression_class": "BOUND_CONSTANT",
                                    "value": child,
                                }
                            )
                            for child in expression["value"]["value"]["children"]
                        ]
                    )
                    + "]"
                )
            else:
                return (
                    "["
                    + ", ".join(
                        [e_to_s(child) for child in expression["value"]["value"]["children"]]
                    )
                    + "]"
                )
        elif expression["value"]["type"]["id"] == "STRUCT":
            if expression["type"] == "VALUE_CONSTANT":
                names = [
                    child["first"]
                    for child in expression["value"]["type"]["type_info"]["child_types"]
                ]
                values = expression["value"]["value"]["children"]
                return (
                    "{"
                    + ",".join(
                        [
                            f"'{name}':"
                            + e_to_s(
                                {
                                    "type": "VALUE_CONSTANT",
                                    "expression_class": "BOUND_CONSTANT",
                                    "value": value,
                                }
                            )
                            for name, value in zip(names, values, strict=True)
                        ]
                    )
                    + "}"
                )
            else:
                raise NotImplementedError("STRUCTs that aren't value constants are not supported")
        else:
            raise NotImplementedError(
                f"Constant type {expression['value']['type']['id']} is not supported"
            )
    elif expression["expression_class"] == "BOUND_COMPARISON":
        return f"{e_to_s(expression['left'])} {comparison_type_to_string_(expression['type'])} {e_to_s(expression['right'])}"
    elif expression["expression_class"] == "BOUND_OPERATOR":
        if expression["type"] in ("OPERATOR_IS_NULL", "OPERATOR_IS_NOT_NULL"):
            operation = "IS NULL" if expression["type"] == "OPERATOR_IS_NULL" else "IS NOT NULL"
            return e_to_s(expression["children"][0]) + " " + operation
        elif expression["type"] in ("COMPARE_IN", "COMPARE_NOT_IN"):
            first, *rest = expression["children"]
            operation = "IN" if expression["type"] == "COMPARE_IN" else "NOT IN"
            return f"{e_to_s(first)} {operation} ({', '.join([e_to_s(child) for child in rest])})"
        elif expression["type"] == "OPERATOR_NOT":
            assert len(expression["children"]) == 1
            return f"NOT {e_to_s(expression['children'][0])}"
        else:
            raise NotImplementedError(f"Operator type {expression['type']} is not supported")
    elif expression["expression_class"] == "BOUND_FUNCTION":
        if expression["name"] == "struct_pack":
            return (
                expression["name"]
                + "("
                + ", ".join(
                    [
                        f"{child_type['first']} := {e_to_s(child)}"
                        for child, child_type in zip(
                            expression["children"],
                            expression["function_data"]["variable_return_type"]["type_info"][
                                "child_types"
                            ],
                            strict=True,
                        )
                    ]
                )
                + ")"
            )
        else:
            return f"{expression['name']}({', '.join([e_to_s(child) for child in expression['children']])})"
    elif expression["expression_class"] == "BOUND_CASE":
        case_checks = [
            f"WHEN {e_to_s(case_check['when_expr'])} THEN {e_to_s(case_check['then_expr'])}"
            for case_check in expression["case_checks"]
        ]
        if expression["else_expr"] is not None:
            case_checks.append(f"ELSE {e_to_s(expression['else_expr'])}")

        return "CASE " + " ".join(case_checks) + " END"
    elif expression["expression_class"] == "BOUND_BETWEEN":
        return f"{e_to_s(expression['input'])} BETWEEN {e_to_s(expression['lower'])} AND {e_to_s(expression['upper'])}"
    elif expression["expression_class"] == "BOUND_CONJUNCTION":
        if expression["type"] == "CONJUNCTION_AND":
            operator = "AND"
        elif expression["type"] == "CONJUNCTION_OR":
            operator = "OR"
        else:
            raise NotImplementedError(f"Conjunction type {expression['type']} is not supported")

        return f"({f' {operator} '.join([e_to_s(child) for child in expression['children']])})"
    else:
        raise NotImplementedError(
            f"Expression class {expression['expression_class']} is not supported expression: {expression}"
        )


def convert_to_sql(
    source: list[dict[str, Any]], bound_column_names: list[str]
) -> tuple[str, dict[str, Any]]:
    bound_column_types: dict[str, Any] = {}
    sql = " AND ".join(
        [
            expression_to_string(
                expression=filter,
                bound_column_names=bound_column_names,
                bound_column_types=bound_column_types,
            )
            for filter in source
        ]
    )
    return sql, bound_column_types


def convert_type_to_sql(fields_with_type_info: dict[str, Any]) -> dict[str, str]:
    return {
        field_name: _type_to_sql_type(type_info)
        for field_name, type_info in fields_with_type_info.items()
    }
