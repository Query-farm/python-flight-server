import msgpack
import pyarrow as pa
import pyarrow.flight as flight

from . import parameter_types


def test_decode_drop_table() -> None:
    serialized = msgpack.packb(
        {
            "type": "table",
            "catalog_name": "test_catalog",
            "schema_name": "test_schema",
            "name": "test_table",
            "ignore_not_found": True,
        }
    )
    decoded = parameter_types.drop_table(flight.Action("drop_table", serialized))
    assert decoded.type == "table"
    assert decoded.catalog_name == "test_catalog"
    assert decoded.schema_name == "test_schema"
    assert decoded.name == "test_table"
    assert decoded.ignore_not_found is True


def test_decode_create_table() -> None:
    real_schema = pa.schema(
        [
            ("column1", pa.int32()),
            ("column2", pa.string()),
        ]
    )
    serialized_schema = real_schema.serialize().to_pybytes()
    serialized = msgpack.packb(
        {
            "catalog_name": "test_catalog",
            "schema_name": "test_schema",
            "table_name": "test_table",
            "arrow_schema": serialized_schema,
            "on_conflict": "error",
            "not_null_constraints": [],
            "unique_constraints": [],
            "check_constraints": ["test1"],
            "primary_key_columns": [],
            "unique_columns": [],
            "multi_key_primary_keys": [],
            "extra_constraints": [],
        },
    )

    decoded = parameter_types.create_table(flight.Action("create_table", serialized))
    assert decoded.catalog_name == "test_catalog"
    assert decoded.schema_name == "test_schema"
    assert decoded.table_name == "test_table"
    assert decoded.arrow_schema == real_schema
    assert decoded.on_conflict == "error"
    assert decoded.not_null_constraints == []
    assert decoded.unique_constraints == []
    assert decoded.check_constraints == ["test1"]
