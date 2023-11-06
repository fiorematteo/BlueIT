from aiohttp import ClientConnectorError
from logging import Logger
from copy import deepcopy
from custom_exceptions import ConnectionStatusError
import custom_func as c_func
import custom_logger as c_logger
from api_connection import ip_analyze, url_analyze
import json

logger: Logger = c_logger.my_logger(name="QRadar")


async def get_last_offenses(config: dict) -> list[dict]:
    """
    ### Get the last offenses from QRadar

    Args:
        - `config`: config["QRadar"] expected

    Returns:
        - `list[dict]`: list of dictionaries of every offense from QRadar
    """
    qradar_url: str = deepcopy(config["server_url"]) + deepcopy(config["url_x_get_offenses"])
    headers: dict = deepcopy(config["headers"])
    num: str = deepcopy(config["number_of_offenses"])
    num = str(int(num) - 1)
    headers["Range"] = f"items=0-{num}"
    try:
        response = await c_func.get(qradar_url, headers=headers, ssl=False)
    except ClientConnectorError:
        logger.error('qradar connection error (get_last_20_offenses()) connection timeout')
        return []
    except ConnectionStatusError as status:
        logger.error(f'qradar connection error (get_last_20_offenses() failed), status code: {status}')
        return []
    assert isinstance(response, list)
    return response


async def qradar_user_assignment(config: dict, offense: dict, user: str) -> None:
    """
    ### Assign user to offense in QRadar

    Args:
        - `config`: config["QRadar"] expected
        - `offense`: offense's dictionary containing all info about one
        - `user_id`: index of user in config["QRadar"]["user_list"]
    """

    offense_id: int = offense["id"]
    user = user.replace(" ", "%20")
    qradar_url: str = deepcopy(config["server_url"]) + deepcopy(config["url_x_assignment"]).replace("%offense_id%", str(offense_id)).replace("%user%", user)
    headers: dict = deepcopy(config["headers"])
    headers["Accept"] = "application/json"
    try:
        await c_func.post(qradar_url, headers=headers, ssl=False)
    except ClientConnectorError:
        logger.error('qradar connection error (qradar_user_assignment()) connection timeout')
    except ConnectionStatusError as status:
        logger.error(f'qradar connection error (qradar_user_assignment() failed), status code: {status}')


async def offense_process(config: dict, offense: dict[str, str]) -> None:
    """
    ### Process the offense

    Create and post note for offense passed if the logic is implemented.

    Args:
        - `config`: config expected
        - `offense`: offense's dictionary containing all info about one
    """
    offense_note: dict = {}
    match offense["description"]:
        case description if description in config["QRadar"]["analyze_url"]["descriptions_list"]:
            await url_analyze(config=config, offense_note=offense_note, url=offense["offense_source"])
            temp_note: str = ""
            for key in offense_note.keys():
                temp_note += offense_note[key]
            offense_note["finalized"] = str(deepcopy(config["QRadar"]["analyze_url"]["note"])).replace("%offense_source%", offense["offense_source"]) + temp_note

        case description if description in config["QRadar"]["analyze_ip"]["descriptions_list"]:
            if str(offense["offense_source"]).split(".")[0] == "10" or (str(offense["offense_source"]).split(".")[0] == "172" and str(offense["offense_source"]).split(".")[1] in [str(x + 16 for x in range(16))]) or (str(offense["offense_source"]).split(".")[0] == "192" and str(offense["offense_source"]).split(".")[1] == "168"):
                return
            await ip_analyze(config=config, offense_note=offense_note, ip=offense["offense_source"])
            temp_note: str = ""
            for key in offense_note.keys():
                temp_note += offense_note[key]
            offense_note["finalized"] = str(deepcopy(config["QRadar"]["analyze_ip"]["note"])).replace("%offense_source%", offense["offense_source"]) + temp_note

        case description if description in config["QRadar"]["simple_wr_note"].keys():
            offense_note["finalized"] = str(deepcopy(config["QRadar"]["simple_wr_note"][description])).replace("%offense_source%", offense["offense_source"])

        case description if description in config["QRadar"]["IIS_note"]["note"].keys():
            IIS_web_site: str = config["QRadar"]["IIS_note"]["IIS_dict"][str(offense["offense_source"]).split(" @ ")[1]][str(offense["offense_source"]).split(" @ ")[0]]
            offense_note["finalized"] = str(deepcopy(config["QRadar"]["IIS_note"]["note"][description])).replace("%IIS_web_site%", IIS_web_site).replace("%offense_source%", offense["offense_source"])

        case _:
            return
    qradar_url: str = deepcopy(config["QRadar"]["server_url"]) + deepcopy(config["QRadar"]["url_x_note"]).replace("%offense_id%", str(offense["id"])).replace("%offense_note_finalized%", offense_note["finalized"])
    headers: dict = deepcopy(config["QRadar"]["headers"])
    try:
        await c_func.post(url=qradar_url, headers=headers, ssl=False)
    except ClientConnectorError:
        logger.error('qradar connection error (offense_process()) connection timeout')
    except ConnectionStatusError as status:
        logger.error(f'qradar connection error (offense_process() failed), status code: {status}')


async def import_txt_list(config: dict, txt_ip_list: dict[str, dict[str, str]]) -> None:
    """
    ### Import new txt ip list

    Import, pars and add to Qradar new bad ip list.

    Args:
        - `config`: config["QRAdar"] expected
        - `txt_ip_list`: config["txt_ip_list] expected
    """
    for name in txt_ip_list.keys():
        ip_list: list[str] = []
        excluded_ip = ["0.0.0.0",
                       "127.0.0.1"
                       ]
        try:
            response = await c_func.get(url=txt_ip_list[name]["url"], headers={})
        except ClientConnectorError:
            logger.error(f'{name} connection error (import_txt_list()) connection timeout')
            continue
        except ConnectionStatusError as status:
            logger.error(f'{name} connection error (import_txt_list() failed), status code: {status}')
            continue
        assert isinstance(response, str)
        for line in response.split("\n"):
            match line:
                case line if "#" in line:
                    continue
                case line if line.split("/")[0] in excluded_ip:
                    continue
                case line if await c_func.is_ip_private(line.split("/")[0]):
                    continue
                case _:
                    ip_list.append(line.split("/")[0])
        ip_list.pop(-1)
        url = deepcopy(config["server_url"]) + deepcopy(config["url_x_set_bulk_load"]).replace("%set_name%", txt_ip_list[name]["set_name"])
        headers: dict = deepcopy(config["headers"])
        headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
            })
        try:
            await c_func.post(url=url, headers=headers, data=json.dumps(ip_list), ssl=False)
        except ClientConnectorError:
            logger.error(f'qradar connection error (import_txt_list()) connection timeout')
            continue
        except ConnectionStatusError as status:
            logger.error(f'qradar connection error (import_txt_list() failed), status code: {status}')
            continue
