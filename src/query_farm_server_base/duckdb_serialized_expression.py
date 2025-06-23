from typing import Any


def _quote_string(value: str) -> str:
    return f"'{value}'"


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


simple_types = {
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
    elif type["id"] in simple_types:
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
        if expression["value"]["type"]["id"] in (
            "VARCHAR",
            "BLOB",
            "BITSTRING",
            "BIT",
            "VARINT",
            "UUID",
        ):
            return _quote_string(expression["value"]["value"])
        elif expression["value"]["type"]["id"] == "BOOLEAN":
            return "True" if expression["value"]["value"] else "False"
        elif expression["value"]["type"]["id"] == "NULL":
            return "null"
        elif expression["value"]["type"]["id"] in (
            "DATE",
            "DECIMAL",
            "BIGINT",
            "INTEGER",
            "FLOAT",
            "DOUBLE",
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
        elif expression["value"]["type"]["id"] == "TIME":
            return f"TIME '{expression['value']['value']}'"
        elif expression["value"]["type"]["id"] == "TIMESTAMP_S":
            return f"make_timestamp({expression['value']['value']}::bigint*1000000)"
        elif expression["value"]["type"]["id"] == "TIMESTAMP_MS":
            return f"make_timestamp({expression['value']['value']}::bigint)"
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
            f"Expression class {expression['expression_class']} is not supported"
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
