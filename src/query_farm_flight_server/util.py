from collections.abc import Iterator
from itertools import islice
from typing import Any, TypeVar

from fuzzywuzzy import fuzz, process


def non_null_values(v: dict[str, Any]) -> dict[str, Any]:
    """
    Return a new dictionary containing only the key-value pairs from the input dictionary 'v' where the value is not None.

    Args:
        v (dict[str, Any]): Input dictionary to filter non-null values from.

    Returns:
        dict[str, Any]: A new dictionary containing only the key-value pairs where the value is not None.
    """
    return {k: v for k, v in v.items() if v is not None}


def first_sentence(text: str) -> str:
    parts = text.split(".", 2)
    return f"{parts[0]}."


T = TypeVar("T")


def chunked_iterator[T](iterator: Iterator[T], chunk_size: int) -> Iterator[list[T]]:
    """
    Chunk an iterator into lists of specified size.

    Args:
        iterator (Iterator[T]): The input iterator to be chunked.
        chunk_size (int): The size of each chunk.

    Yields:
        Iterator[list[T]]: An iterator yielding lists of elements from the input iterator.
    """
    iterator = iter(iterator)
    while True:
        chunk = list(islice(iterator, chunk_size))
        if not chunk:
            break
        yield chunk


def suggest_corrections(user_input: str, options: list[str]) -> list[str] | None:
    """
    Suggest corrections for user input based on a list of options.

    Args:
        user_input (str): The input provided by the user.
        options (list[str]): A list of options to compare the user input against.

    Returns:
        list[str] | None: A list of suggested corrections for the user input, or None if no corrections are found.
    """
    possible_results = list(
        map(
            lambda v: v[0],
            process.extract(user_input, options, scorer=fuzz.ratio, limit=1),
        )
    )
    if len(possible_results) == 0:
        return None
    return possible_results


URL_SAFE_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_:="
URL_SAFE_CHARS_COUNT = len(URL_SAFE_CHARS)


def hex_to_url_safe_characters(hex_str: str) -> str:
    """
    Converts a hexadecimal string to URL-safe characters using an encoding scheme.

        Args:
            hex_str (str): The hexadecimal string to be converted.

        Returns:
            str: The URL-safe characters encoded using Base62.
    """
    hash_int = int(hex_str, 16)

    encoded_value = ""

    while hash_int > 0:
        hash_int, remainder = divmod(hash_int, URL_SAFE_CHARS_COUNT)
        encoded_value = URL_SAFE_CHARS[remainder] + encoded_value

    return encoded_value
