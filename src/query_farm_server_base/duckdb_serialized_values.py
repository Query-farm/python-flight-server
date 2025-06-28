import base64
import math
import uuid
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Discriminator, Field, Tag, field_validator


class SerializedValueBase(BaseModel):
    is_null: bool


class SerializedValueValue_128bits(BaseModel):
    lower: int
    upper: int


def decode_base64(cls: Any, value: Any) -> bytes:
    try:
        return base64.b64decode(value)
    except Exception as e:
        raise ValueError(f"Invalid Base64 encoded value: {e}") from e


class SerializedValueValue_base64(BaseModel):
    base64: bytes
    # Do the decoding of the value here for the user.
    _validate_base64 = field_validator("base64", mode="before")(decode_base64)


class SerializedValueTypeInfo_list(BaseModel):
    alias: str
    child_type: "AllValidTypeIdAndInfo"
    modifiers: list[Any]
    type: Literal["LIST_TYPE_INFO"] = "LIST_TYPE_INFO"


class SerializedValueType_list(BaseModel):
    id: Literal["LIST"] = "LIST"
    type_info: SerializedValueTypeInfo_list

    def sql(self) -> str:
        return f"{self.type_info.child_type.sql()}[]"


class SerializedValueValue_list(BaseModel):
    children: list["SerializedValue"]


class SerializedValue_list(SerializedValueBase):
    type: SerializedValueType_list
    value: SerializedValueValue_list

    def sql(self) -> str:
        return "[" + ", ".join([child.sql() for child in self.value.children]) + "]"


class SerializedValueType_bigint(BaseModel):
    id: Literal["BIGINT"] = "BIGINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_bigint(SerializedValueBase):
    type: SerializedValueType_bigint
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        return str(self.value)


class SerializedValueType_bit(BaseModel):
    id: Literal["BIT"] = "BIT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_bit(SerializedValueBase):
    type: SerializedValueType_bit
    value: bytes | SerializedValueValue_base64 | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        if isinstance(self.value, SerializedValueValue_base64):
            data = self.value.base64
        else:
            data = self.value

        if not data or len(data) < 2:
            return ""

        padding_bits = data[0]
        bit_data = data[1:]

        # Convert all bytes to bits
        bits = "".join(f"{byte:08b}" for byte in bit_data)

        # Remove the padding bits from the end
        if padding_bits:
            bits = bits[padding_bits:]

        return f"'{bits}'"


class SerializedValueType_blob(BaseModel):
    id: Literal["BLOB"] = "BLOB"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_blob(SerializedValueBase):
    type: SerializedValueType_blob
    value: str | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        return f"'{self.value.replace("'", "''")}'"


class SerializedValueType_boolean(BaseModel):
    id: Literal["BOOLEAN"] = "BOOLEAN"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_boolean(SerializedValueBase):
    type: SerializedValueType_boolean
    value: bool | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"

        return str("true" if self.value else "false")


class SerializedValueType_date(BaseModel):
    id: Literal["DATE"] = "DATE"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_date(SerializedValueBase):
    type: SerializedValueType_date
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        if self.value == -2147483647:
            return "'-infinity'"
        elif self.value == 2147483647:
            return "'infinity'"
        formatted_date = (date(1970, 1, 1) + timedelta(days=self.value)).isoformat()
        return f"'{formatted_date}'"


class SerializedValueTypeInfo_decimal(BaseModel):
    width: int
    scale: int


class SerializedValueType_decimal(BaseModel):
    id: Literal["DECIMAL"] = "DECIMAL"
    type_info: SerializedValueTypeInfo_decimal

    def sql(self) -> str:
        return f"DECIMAL({self.type_info.width}, {self.type_info.scale})"


class SerializedValue_decimal(SerializedValueBase):
    type: SerializedValueType_decimal
    value: int | SerializedValueValue_128bits | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        scale = self.type.type_info.scale

        if isinstance(self.value, SerializedValueValue_128bits):
            # Reconstruct full integer (assuming 64-bit halves)
            combined = (self.value.upper << 64) | self.value.lower

            # Convert from unsigned to signed (two's complement if necessary)
            if self.value.upper & (1 << 63):
                combined -= 1 << 128

            decimal_value = Decimal(combined)
        elif isinstance(self.value, int):
            # Assume it's a simple int (64-bit)
            decimal_value = Decimal(self.value)
        else:
            raise NotImplementedError("Invalid Decimal value storage")

        return str(decimal_value / Decimal(10) ** scale)


class SerializedValueType_double(BaseModel):
    id: Literal["DOUBLE"] = "DOUBLE"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_double(SerializedValueBase):
    type: SerializedValueType_double
    value: float | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        if math.isinf(self.value):
            if self.value > 0:
                return "'infinity'"
            return "'-infinity'"
        elif math.isnan(self.value):
            return "'nan'"
        return str(self.value)


class SerializedValueType_float(BaseModel):
    id: Literal["FLOAT"] = "FLOAT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_float(SerializedValueBase):
    type: SerializedValueType_float
    value: float | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        if math.isinf(self.value):
            if self.value > 0:
                return "'infinity'"
            return "'-infinity'"
        elif math.isnan(self.value):
            return "'nan'"
        return str(self.value)


class SerializedValueType_hugeint(BaseModel):
    id: Literal["HUGEINT"] = "HUGEINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_hugeint(SerializedValueBase):
    type: SerializedValueType_hugeint
    value: SerializedValueValue_128bits | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        upper = self.value.upper
        lower = self.value.lower
        result = (upper << 64) | lower

        # If the highest bit (bit 127) is set, interpret as negative
        if upper & (1 << 63):
            result -= 1 << 128

        return str(result)


class SerializedValueType_integer(BaseModel):
    id: Literal["INTEGER"] = "INTEGER"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_integer(SerializedValueBase):
    type: SerializedValueType_integer
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"

        return str(self.value)


class SerializedValueType_interval(BaseModel):
    id: Literal["INTERVAL"] = "INTERVAL"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValueValue_interval(BaseModel):
    months: int
    days: int
    micros: int


class SerializedValue_interval(SerializedValueBase):
    type: SerializedValueType_interval
    value: SerializedValueValue_interval | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        return (
            "INTERVAL '"
            + f"{self.value.months} months {self.value.days} days {self.value.micros} us"
            + "'"
        )


class SerializedValueType_null(BaseModel):
    id: Literal["NULL"] = "NULL"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_null(SerializedValueBase):
    type: SerializedValueType_null
    value: None

    def sql(self) -> str:
        return "null"


class SerializedValueType_smallint(BaseModel):
    id: Literal["SMALLINT"] = "SMALLINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_smallint(SerializedValueBase):
    type: SerializedValueType_smallint
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"

        return str(self.value)


class SerializedValueType_time(BaseModel):
    id: Literal["TIME"] = "TIME"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_time(SerializedValueBase):
    type: SerializedValueType_time
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        t = timedelta(microseconds=self.value)
        hours, remainder = divmod(t.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        return time(hours, minutes, seconds, microsecond=t.microseconds).strftime("%H:%M:%S.%f")


class SerializedValueType_time_with_time_zone(BaseModel):
    id: Literal["TIME WITH TIME ZONE"] = "TIME WITH TIME ZONE"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_time_with_time_zone(SerializedValueBase):
    type: SerializedValueType_time_with_time_zone
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        t = timedelta(microseconds=self.value)
        hours, remainder = divmod(t.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        return (
            "TIMETZ '"
            + time(hours, minutes, seconds, microsecond=t.microseconds).strftime("%H:%M:%S.%f")
            + "'"
        )


class SerializedValueType_timestamp_with_time_zone(BaseModel):
    id: Literal["TIMESTAMP WITH TIME ZONE"] = "TIMESTAMP WITH TIME ZONE"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_timestamp_with_time_zone(SerializedValueBase):
    type: SerializedValueType_timestamp_with_time_zone
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        return (
            "TIMESTAMPTZ '"
            + datetime.fromtimestamp(int(self.value) / 1_000_000, tz=UTC).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
            + "'"
        )


class SerializedValueType_timestamp_ms(BaseModel):
    id: Literal["TIMESTAMP_MS"] = "TIMESTAMP_MS"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_timestamp_ms(SerializedValueBase):
    type: SerializedValueType_timestamp_ms
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        dt = datetime.fromtimestamp(self.value / 1000, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class SerializedValueType_timestamp_ns(BaseModel):
    id: Literal["TIMESTAMP_NS"] = "TIMESTAMP_NS"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_timestamp_ns(SerializedValueBase):
    type: SerializedValueType_timestamp_ns
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"

        return f"make_timestamp_ns({self.value}::bigint)"


class SerializedValueType_timestamp_s(BaseModel):
    id: Literal["TIMESTAMP_S"] = "TIMESTAMP_S"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_timestamp_s(SerializedValueBase):
    type: SerializedValueType_timestamp_s
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        dt = datetime.fromtimestamp(self.value / 1000, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S")


class SerializedValueType_tinyint(BaseModel):
    id: Literal["TINYINT"] = "TINYINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_tinyint(SerializedValueBase):
    type: SerializedValueType_tinyint
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"

        return str(self.value)


class SerializedValueType_ubigint(BaseModel):
    id: Literal["UBIGINT"] = "UBIGINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_ubigint(SerializedValueBase):
    type: SerializedValueType_ubigint
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"

        return str(self.value)


class SerializedValueType_uhugeint(BaseModel):
    id: Literal["UHUGEINT"] = "UHUGEINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_uhugeint(SerializedValueBase):
    type: SerializedValueType_uhugeint
    value: SerializedValueValue_128bits | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        upper = self.value.upper
        lower = self.value.lower
        return str((upper << 64) | lower)


class SerializedValueType_uinteger(BaseModel):
    id: Literal["UINTEGER"] = "UINTEGER"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_uinteger(SerializedValueBase):
    type: SerializedValueType_uinteger
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value
        return str(self.value)


class SerializedValueType_usmallint(BaseModel):
    id: Literal["USMALLINT"] = "USMALLINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_usmallint(SerializedValueBase):
    type: SerializedValueType_usmallint
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value
        return str(self.value)


class SerializedValueType_utinyint(BaseModel):
    id: Literal["UTINYINT"] = "UTINYINT"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_utinyint(SerializedValueBase):
    type: SerializedValueType_utinyint
    value: int | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value
        return str(self.value)


class SerializedValueType_uuid(BaseModel):
    id: Literal["UUID"] = "UUID"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_uuid(SerializedValueBase):
    type: SerializedValueType_uuid
    value: SerializedValueValue_128bits | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value
        upper = self.value.upper & ((1 << 64) - 1)  # Convert to unsigned if needed
        lower = self.value.lower

        # Combine into 128-bit integer
        combined = (upper << 64) | lower

        # Convert to 16 bytes (big-endian)
        bytes_ = combined.to_bytes(16, byteorder="big")

        # Create UUID from bytes
        u = uuid.UUID(bytes=bytes_)

        return str(u)


class SerializedValueType_varchar(BaseModel):
    id: Literal["VARCHAR"] = "VARCHAR"
    type_info: None

    def sql(self) -> str:
        return self.id


class SerializedValue_varchar(SerializedValueBase):
    type: SerializedValueType_varchar
    value: str | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        return f"'{self.value.replace("'", "''")}'"


class SerializedValueType_varint(BaseModel):
    id: Literal["VARINT"] = "VARINT"
    type_info: None

    def sql(self) -> str:
        return self.id


def _varint_get_byte_array(blob: bytes) -> tuple[list[int], bool]:
    if len(blob) < 4:
        raise ValueError("Invalid blob size.")

    # Determine if the number is negative
    is_negative = (blob[0] & 0x80) == 0

    # Extract byte array starting from the 4th byte
    byte_array = [~b & 255 for b in blob[3:]] if is_negative else list(blob[3:])
    return byte_array, is_negative


class SerializedValue_varint(SerializedValueBase):
    type: SerializedValueType_varint
    value: bytes | SerializedValueValue_base64 | None = None

    def sql(self) -> str:
        if self.is_null:
            return "null"
        assert self.value

        decimal_string = ""
        if isinstance(self.value, SerializedValueValue_base64):
            byte_array, is_negative = _varint_get_byte_array(self.value.base64)
        else:
            byte_array, is_negative = _varint_get_byte_array(self.value)

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


def get_discriminator_value(v: Any) -> str:
    return v.get("type").get("id")


AllValidTypeIdAndInfo = Union[
    SerializedValueType_boolean,
    SerializedValueType_bigint,
    SerializedValueType_bit,
    SerializedValueType_blob,
    SerializedValueType_date,
    SerializedValueType_decimal,
    SerializedValueType_double,
    SerializedValueType_float,
    SerializedValueType_hugeint,
    SerializedValueType_integer,
    SerializedValueType_interval,
    SerializedValueType_list,
    SerializedValueType_null,
    SerializedValueType_smallint,
    "SerializedValueType_struct",
    SerializedValueType_time,
    SerializedValueType_time_with_time_zone,
    SerializedValueType_timestamp_with_time_zone,
    SerializedValueType_timestamp_ms,
    SerializedValueType_timestamp_ns,
    SerializedValueType_timestamp_s,
    SerializedValueType_tinyint,
    SerializedValueType_ubigint,
    SerializedValueType_uhugeint,
    SerializedValueType_uinteger,
    SerializedValueType_usmallint,
    SerializedValueType_utinyint,
    SerializedValueType_uuid,
    SerializedValueType_varchar,
    SerializedValueType_varint,
]


class SerializedValueTypeInfoChild_struct(BaseModel):
    first: str
    second: AllValidTypeIdAndInfo


class SerializedValueTypeInfo_struct(BaseModel):
    child_types: list[SerializedValueTypeInfoChild_struct]
    type: Literal["STRUCT_TYPE_INFO"] = "STRUCT_TYPE_INFO"
    alias: str | None = None
    modifiers: list[Any] | None = None


class SerializedValueType_struct(BaseModel):
    id: Literal["STRUCT"] = "STRUCT"
    type_info: SerializedValueTypeInfo_struct

    def sql(self) -> str:
        return (
            "STRUCT("
            + ",".join(
                [f'"{child.first}" {child.second.sql()}' for child in self.type_info.child_types]
            )
            + ")"
        )


class SerializedValueValue_struct(BaseModel):
    children: list["SerializedValue"]


class SerializedValue_struct(SerializedValueBase):
    type: SerializedValueType_struct
    value: SerializedValueValue_struct

    def sql(self) -> str:
        names = [child.first for child in self.type.type_info.child_types]
        values = self.value.children
        return (
            "{"
            + ",".join(
                [f"'{name}':" + value.sql() for name, value in zip(names, values, strict=True)]
            )
            + "}"
        )


SerializedValue = Annotated[
    Annotated[SerializedValue_bigint, Tag("BIGINT")]
    | Annotated[SerializedValue_bit, Tag("BIT")]
    | Annotated[SerializedValue_blob, Tag("BLOB")]
    | Annotated[SerializedValue_boolean, Tag("BOOLEAN")]
    | Annotated[SerializedValue_date, Tag("DATE")]
    | Annotated[SerializedValue_decimal, Tag("DECIMAL")]
    | Annotated[SerializedValue_double, Tag("DOUBLE")]
    | Annotated[SerializedValue_float, Tag("FLOAT")]
    | Annotated[SerializedValue_hugeint, Tag("HUGEINT")]
    | Annotated[SerializedValue_integer, Tag("INTEGER")]
    | Annotated[SerializedValue_interval, Tag("INTERVAL")]
    | Annotated[SerializedValue_list, Tag("LIST")]
    | Annotated[SerializedValue_null, Tag("NULL")]
    | Annotated[SerializedValue_smallint, Tag("SMALLINT")]
    | Annotated[SerializedValue_struct, Tag("STRUCT")]
    | Annotated[SerializedValue_time, Tag("TIME")]
    | Annotated[SerializedValue_time_with_time_zone, Tag("TIME WITH TIME ZONE")]
    | Annotated[SerializedValue_timestamp_with_time_zone, Tag("TIMESTAMP WITH TIME ZONE")]
    | Annotated[SerializedValue_timestamp_ms, Tag("TIMESTAMP_MS")]
    | Annotated[SerializedValue_timestamp_ns, Tag("TIMESTAMP_NS")]
    | Annotated[SerializedValue_timestamp_s, Tag("TIMESTAMP_S")]
    | Annotated[SerializedValue_tinyint, Tag("TINYINT")]
    | Annotated[SerializedValue_ubigint, Tag("UBIGINT")]
    | Annotated[SerializedValue_uhugeint, Tag("UHUGEINT")]
    | Annotated[SerializedValue_uinteger, Tag("UINTEGER")]
    | Annotated[SerializedValue_usmallint, Tag("USMALLINT")]
    | Annotated[SerializedValue_utinyint, Tag("UTINYINT")]
    | Annotated[SerializedValue_uuid, Tag("UUID")]
    | Annotated[SerializedValue_varchar, Tag("VARCHAR")]
    | Annotated[SerializedValue_varint, Tag("VARINT")],
    Discriminator(get_discriminator_value),
]


class Context(BaseModel):
    bound_column_names: list[str]
    bound_column_types: dict[str, str]


def inject_context(obj: Any, context: Context) -> None:
    if isinstance(obj, BaseWithContext):
        obj.parse_context_ = context
        for _field_name, field_value in obj.__dict__.items():
            if isinstance(field_value, BaseWithContext):
                inject_context(field_value, context)
            elif isinstance(field_value, list):
                for item in field_value:
                    inject_context(item, context)
            elif isinstance(field_value, dict):
                for item in field_value.values():
                    inject_context(item, context)


class BaseWithContext(BaseModel):
    parse_context_: Context | None = Field(default=None, exclude=True)

    # def model_post_init(self) -> None:
    #     if self.parse_context_ is None:
    #         self.parse_context_ = parse_context__
    #     assert self.parse_context_, "parse_context_ must be set before injecting context"
    #     inject_context(self, self.parse_context_)  # recursive injection


class ExpressionBase(BaseWithContext):
    alias: str | None = None
    query_location: int | None = None


class ExpressionBoundConstant(ExpressionBase):
    expression_class: Literal["BOUND_CONSTANT"] = "BOUND_CONSTANT"
    type: Literal["VALUE_CONSTANT"] = "VALUE_CONSTANT"
    value: SerializedValue

    def sql(self) -> str:
        return self.value.sql()


class ExpressionBoundColumnRefBinding(BaseModel):
    table_index: int
    column_index: int


class ExpressionBoundColumnRef(ExpressionBase, BaseWithContext):
    expression_class: Literal["BOUND_COLUMN_REF"] = "BOUND_COLUMN_REF"
    type: str
    depth: int
    binding: ExpressionBoundColumnRefBinding
    return_type: AllValidTypeIdAndInfo

    def sql(self) -> str:
        assert self.parse_context_
        column_name = self.parse_context_.bound_column_names[self.binding.column_index]
        self.parse_context_.bound_column_types[column_name] = self.return_type.sql()
        return f'"{column_name}"'


comparison_type_to_sql_operator: dict[str, str] = {
    "COMPARE_EQUAL": "=",
    "COMPARE_NOTEQUAL": "!=",
    "COMPARE_LESSTHAN": "<",
    "COMPARE_GREATERTHAN": ">",
    "COMPARE_LESSTHANOREQUALTO": "<=",
    "COMPARE_GREATERTHANOREQUALTO": ">=",
    "COMPARE_DISTINCT_FROM": "IS DISTINCT FROM",
    "COMPARE_NOT_DISTINCT_FROM": "IS NOT DISTINCT FROM",
}

AnyExpression = Union[
    ExpressionBoundConstant,
    ExpressionBoundColumnRef,
    "ExpressionBoundComparison",
    "ExpressionBoundCast",
    "ExpressionBoundFunction",
    "ExpressionBoundOperator",
    "ExpressionBoundCase",
    "ExpressionBoundBetween",
    "ExpressionBoundConjunction",
]


class ExpressionBoundConjunction(ExpressionBase):
    expression_class: Literal["BOUND_CONJUNCTION"] = "BOUND_CONJUNCTION"
    type: Literal["CONJUNCTION_AND", "CONJUNCTION_OR"]
    children: list[AnyExpression]

    def sql(self) -> str:
        operator = "AND" if self.type == "CONJUNCTION_AND" else "OR"
        return "(" + f" {operator} ".join([child.sql() for child in self.children]) + ")"


class ExpressionBoundBetween(ExpressionBase):
    expression_class: Literal["BOUND_BETWEEN"] = "BOUND_BETWEEN"
    input: AnyExpression
    lower: AnyExpression
    upper: AnyExpression

    def sql(self) -> str:
        return f"{self.input.sql()} BETWEEN {self.lower.sql()} AND {self.upper.sql()}"


class ExpressionBoundCast(ExpressionBase):
    expression_class: Literal["BOUND_CAST"] = "BOUND_CAST"
    child: AnyExpression
    return_type: AllValidTypeIdAndInfo

    def sql(self) -> str:
        return f"CAST({self.child.sql()} AS {self.return_type.sql()})"


class ExpressionBoundCaseCaseCheck(BaseModel):
    when_expr: AnyExpression
    then_expr: AnyExpression


class ExpressionBoundCase(ExpressionBase):
    expression_class: Literal["BOUND_CASE"] = "BOUND_CASE"
    case_checks: list[ExpressionBoundCaseCaseCheck]
    else_expr: AnyExpression | None = None

    def sql(self) -> str:
        case_checks = [
            f"WHEN {case_check.when_expr.sql()} THEN {case_check.then_expr.sql()}"
            for case_check in self.case_checks
        ]
        if self.else_expr:
            case_checks.append(f"ELSE {self.else_expr.sql()}")

        return "CASE " + " ".join(case_checks) + " END"


class ExpressionBoundOperator(ExpressionBase):
    expression_class: Literal["BOUND_OPERATOR"] = "BOUND_OPERATOR"
    type: Literal[
        "OPERATOR_IS_NULL", "OPERATOR_IS_NOT_NULL", "COMPARE_IN", "COMPARE_NOT_IN", "OPERATOR_NOT"
    ]
    children: list[AnyExpression]

    def sql(self) -> str:
        if self.type in ("OPERATOR_IS_NULL", "OPERATOR_IS_NOT_NULL"):
            operation = "IS NULL" if self.type == "OPERATOR_IS_NULL" else "IS NOT NULL"
            return self.children[0].sql() + " " + operation
        elif self.type in ("COMPARE_IN", "COMPARE_NOT_IN"):
            first, *rest = self.children
            operation = "IN" if self.type == "COMPARE_IN" else "NOT IN"
            return f"{first.sql()} {operation} ({', '.join([child.sql() for child in rest])})"
        elif self.type == "OPERATOR_NOT":
            assert len(self.children) == 1
            return f"NOT {self.children[0].sql()}"
        else:
            raise ValueError(f"Unsupported operator type: {self.type}")


class ExpressionBoundFunctionFunctionData(BaseModel):
    variable_return_type: AllValidTypeIdAndInfo


class ExpressionBoundFunction(ExpressionBase):
    expression_class: Literal["BOUND_FUNCTION"] = "BOUND_FUNCTION"
    name: str
    return_type: AllValidTypeIdAndInfo
    children: list[AnyExpression]
    arguments: list[AllValidTypeIdAndInfo] | None = None
    original_arguments: list[AllValidTypeIdAndInfo] | None = None
    has_serialize: bool
    is_operator: bool
    function_data: ExpressionBoundFunctionFunctionData | None = None

    def sql(self) -> str:
        if self.name == "struct_pack":
            assert self.function_data is not None
            result_struct = self.function_data.variable_return_type
            assert isinstance(result_struct, SerializedValueType_struct)

            return (
                self.name
                + "("
                + ", ".join(
                    [
                        f"{child_type.first} := {child.sql()}"
                        for child, child_type in zip(
                            self.children,
                            result_struct.type_info.child_types,
                            strict=True,
                        )
                    ]
                )
                + ")"
            )
        else:
            return f"{self.name}({', '.join([child.sql() for child in self.children])})"


class ExpressionBoundComparison(ExpressionBase):
    left: AnyExpression
    right: AnyExpression

    type: Literal[
        "COMPARE_EQUAL",
        "COMPARE_NOTEQUAL",
        "COMPARE_LESSTHAN",
        "COMPARE_GREATERTHAN",
        "COMPARE_LESSTHANOREQUALTO",
        "COMPARE_GREATERTHANOREQUALTO",
        "COMPARE_DISTINCT_FROM",
        "COMPARE_NOT_DISTINCT_FROM",
    ]

    def sql(self) -> str:
        operator = comparison_type_to_sql_operator.get(self.type)
        if operator is None:
            raise ValueError(f"Unsupported comparison type: {self.type}")

        return f"{self.left.sql()} {operator} {self.right.sql()}"


SerializedExpressionContents = Annotated[
    Annotated[ExpressionBoundConstant, Tag("BOUND_CONSTANT")]
    | Annotated[ExpressionBoundColumnRef, Tag("BOUND_COLUMN_REF")]
    | Annotated[ExpressionBoundComparison, Tag("BOUND_COMPARISON")]
    | Annotated[ExpressionBoundCast, Tag("BOUND_CAST")]
    | Annotated[ExpressionBoundFunction, Tag("BOUND_FUNCTION")]
    | Annotated[ExpressionBoundOperator, Tag("BOUND_OPERATOR")]
    | Annotated[ExpressionBoundCase, Tag("BOUND_CASE")]
    | Annotated[ExpressionBoundBetween, Tag("BOUND_BETWEEN")]
    | Annotated[ExpressionBoundConjunction, Tag("BOUND_CONJUNCTION")],
    Discriminator(lambda v: v.get("expression_class")),
]


class SerializedExpression(BaseWithContext):
    contents: SerializedExpressionContents
