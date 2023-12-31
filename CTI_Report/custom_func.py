import json
import asyncio
import aiohttp
import custom_exceptions


async def write_json(file_name: str, my_dict: dict) -> None:
    """
    ### Write a json file

    Write a json file from a given dict

    The `file_name` can contain a path

    Args:
        - `file_name`: name for the json file
        - `my_dict`: dict to be converted in json
    """
    json_string = json.dumps(my_dict)
    with open(file_name, "w") as file:
        file.write(json_string)


async def read_json(file_name: str) -> dict:
    """
    ### Read a json file

    Read json file and convert to dict

    The `file_name` can contain a path

    Args:
        - `file_name`: name of the json file

    Returns:
        - `dict`: dict of json file
    """
    with open(file_name, "r", encoding="UTF-8") as file:
        config = json.loads(file.read())
    return config


async def string_spacer(word: str) -> str:
    """
    ### Space strings before Capital

    Add a space before each capital letter of the given string

        abuseConfidenceScore -> abuse Confidence Score

    Args:
        - `word`: string that needs to be properly spaced

    Returns:
        - `str`: Spaced string
    """
    result: str = ""
    for char in word:
        if char.isupper():
            result += " " + char.upper()
        else:
            result += char
    return result


async def post(url: str, headers: dict[str, str], data=None, ssl=True) -> list[dict] | dict | str:
    """
    ### Perform custom async HTTP POST request

    Args:
        - `url`: url for the POST
        - `headers`: headers for the POST
        - `data`: miscellaneous data to POST. Defaults to None.
        - `ssl`: check ssl certificate. Defaults to True.

    Raises:
        - `ConnectionStatusError`: connection status is not 200 or 201

    Returns:
        - `list[dict]` | `dict` | `str`: response json or str
    """
    status: int = 0
    for c in range(5):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl)) as session:
            async with session.post(url=url, headers=headers, data=data) as response:
                if response.status == 200 or response.status == 201:
                    match response.content_type:
                        case "application/json":
                            return await response.json()
                        case "text/plain":
                            return await response.text()
                status = response.status
        await asyncio.sleep(2 ** c)
    raise custom_exceptions.ConnectionStatusError(status)


async def get(url: str, headers: dict[str, str], params=None, ssl=True) -> list[dict] | dict | str:
    """
    ### Perform custom async HTTP GET request

    Args:
        - `url`: url for the GET
        - `headers`: headers for the GET
        - `params`: miscellaneous parameters for GET. Defaults to None.
        - `ssl`: check ssl certificate. Defaults to True.

    Raises:
        - `ConnectionStatusError`: connection status is not 200 or 201

    Returns:
        - `list[dict]` | `dict` | `str`: response json or str
    """
    status: int = 0
    for c in range(5):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl)) as session:
            async with session.get(url=url, headers=headers, params=params) as response:
                if response.status == 200 or response.status == 201:
                    match response.content_type:
                        case "application/json":
                            return await response.json()
                        case "text/plain" | "application/octet-stream":
                            return await response.text()
                status = response.status
        await asyncio.sleep(2 ** c)
    raise custom_exceptions.ConnectionStatusError(status)
