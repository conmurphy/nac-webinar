"""
JMESPath-based JSON query library for Robot Framework
Provides high-performance JSON querying as an alternative to JSONPath

Requirements:
    pip install jmespath
"""

import jmespath
from typing import Any, List


def json_search_string(data: Any, expression: str) -> str:
    """
    Execute a JMESPath query and return a single string result.

    This keyword executes a JMESPath expression against JSON data and returns
    the first result as a string. If the result is a list, the first element
    is returned. If no results are found, returns an empty string.

    Args:
        data: The JSON data to query (typically from ${response.json()})
        expression: A JMESPath expression string

    Returns:
        A string value, or empty string if no match

    Examples:
        | ${result}= | Json Search String | ${json} | imdata[0].*.attributes.name | [0] |
        | ${result}= | Json Search String | ${json} | imdata[0].*.children[?fvSubnet].fvSubnet.attributes.ip | [0] |
    """
    try:
        result = jmespath.search(expression, data)

        # Handle different result types
        if result is None:
            return ""
        elif isinstance(result, list):
            # Return first element if list, or empty string if empty list
            return str(result[0]) if result else ""
        else:
            return str(result)

    except Exception as e:
        raise RuntimeError(f"JMESPath query failed: {expression}\nError: {str(e)}")


def json_search_list(data: Any, expression: str) -> List[Any]:
    """
    Execute a JMESPath query and return results as a list.

    This keyword executes a JMESPath expression against JSON data and returns
    the results as a list. If the result is not already a list, it will be
    wrapped in a list. Returns an empty list if no matches are found.

    Args:
        data: The JSON data to query (typically from ${response.json()})
        expression: A JMESPath expression string

    Returns:
        A list of results, or empty list if no matches

    Examples:
        | ${results}= | Json Search List | ${json} | imdata[0].*.children[*].fvSubnet.attributes.ip |
        | ${names}= | Json Search List | ${json} | imdata[0].*.attributes.name |
    """
    try:
        result = jmespath.search(expression, data)

        # Handle different result types
        if result is None:
            return []
        elif isinstance(result, list):
            return result
        else:
            # Wrap single result in a list
            return [result]

    except Exception as e:
        raise RuntimeError(f"JMESPath query failed: {expression}\nError: {str(e)}")