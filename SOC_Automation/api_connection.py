import asyncio
from logging import Logger
from async_dns.core import types
from async_dns.resolver import ProxyResolver
import custom_logger as c_logger
from custom_exceptions import ConnectionStatusError
import custom_func as c_func
from aiohttp import ClientConnectorError
from collections import Counter
import json
from copy import deepcopy
from pysafebrowsing import SafeBrowsing

logger: Logger = c_logger.my_logger(name="Api_connection")


async def ip_analyze(config: dict, offense_note: dict[str, str], ip: str) -> None:
    """
    ### Start all func that analyze an ip

    Args:
        - `config`: config dict expected
        - `offense_note`: dict for the offense's note
        - `ip`: ip to analyze
    """
    await asyncio.gather(abuseip(config["AbuseIp"], offense_note, ip),
                         criminalip(config["CriminalIp"], offense_note, ip),
                         ipregistry(config["IpRegistry"], offense_note, ip)
                         )


async def url_analyze(config: dict, offense_note: dict[str, str], url: str) -> None:
    """
    ### Start all func that analyze an url

    Args:
        - `config`: config dict expected
        - `offense_note`: dict for the offense's note
        - `url`: url to analyze
    """
    try:
        res, cached = await ProxyResolver().query(url, types.A)
        ip = str(res.an[-1].data.data)
    except IndexError:
        logger.error(f'url_analyze ip resolution error (url_analyze({url}))')
        await asyncio.gather(urlscan(config["UrlScan"], offense_note, url),
                             virustotal(config["VirusTotal"], offense_note, url),
                             pulsedive(config["Pulsedive"], offense_note, url),
                             criminalip_url(config["CriminalIp_url"], offense_note, url),
                             google_safe_browsing(config["Google_Safe_Browsing"], offense_note, url)
                             )
        return
    await asyncio.gather(urlscan(config["UrlScan"], offense_note, url),
                         virustotal(config["VirusTotal"], offense_note, url),
                         abuseip(config["AbuseIp"], offense_note, ip),
                         pulsedive(config["Pulsedive"], offense_note, url),
                         criminalip(config["CriminalIp"], offense_note, ip),
                         # criminalip_url(config["CriminalIp_url"], offense_note, url),
                         google_safe_browsing(config["Google_Safe_Browsing"], offense_note, url),
                         ipregistry(config["IpRegistry"], offense_note, ip)
                         )


async def urlscan(config: dict, offense_note: dict[str, str], url: str) -> None:
    """
    ### Analyze url on UrlScan

    Args:
        - `config`: config["UrlScan"] expected
        - `offense_note`: dict for the offense's note
        - `url`: url to analyze
    """
    if not config["in_use"]:
        return

    name: str = "urlscan"
    Name: str = "UrlScan"

    data: str = json.dumps({"url": f"http://{url}/", "visibility": "public"})
    try:
        response = await c_func.post(url=config["url"], headers=config["headers"], data=data)
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}(), post) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}(), post failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)

    await asyncio.sleep(60)
    try:
        response = await c_func.get(url=response["api"], headers=config["headers"])
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}(), get) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}(), get failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)

    urlscan_note: str = ""
    is_malicious_list: list = []
    for key in response["verdicts"].keys():
        urlscan_note += f' {key} score: {response["verdicts"][key]["score"]}' * config[f"show_{key}_score"]
        is_malicious_list.append(response["verdicts"][key]["malicious"])
    c = Counter(is_malicious_list)
    urlscan_note += f' malicious counter: {str(c).replace("Counter", "")}' * config["show_malicious_counter"]
    offense_note[name] = f'\n Da {Name}:[{urlscan_note}].'


async def abuseip(config: dict, offense_note: dict[str, str], ip: str) -> None:
    """
    ### Analyze ip on AbuseIp

    Args:
        - `config`: config["AbuseIp"] expected
        - `offense_note`: dict for the offense's note
        - `ip`: ip to analyze.
    """
    if not config["in_use"]:
        return

    name: str = "abuseip"
    Name: str = "AbuseIp"

    querystring: dict[str, str] = {
        'ipAddress': ip,
        'maxAgeInDays': config["maxAgeInDays_of_ip_reports"]
        }
    try:
        response = await c_func.get(url=config["url"], headers=config["headers"], params=querystring)
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}()) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}() failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)
    abuseip_note: str = ""
    for key in response["data"].keys():
        key_x_note = await c_func.string_spacer(key)
        abuseip_note += f' {key_x_note.lower().replace("is ", "")}: {response["data"][key]}' * config[f"show_{key}"]

    offense_note[name] = f'\n Da {Name}:[{abuseip_note}].'


async def virustotal(config: dict, offense_note: dict[str, str], url: str) -> None:
    """
    ### Analyze url on VirusTotal

    Args:
        - `config`: config["VirusTotal"] expected
        - `offense_note`: dict for the offense's note
        - `url`: url to analyze
    """
    if not config["in_use"]:
        return

    name: str = "virustotal"
    Name: str = "VirusTotal"

    payload: str = f"url={url}"
    try:
        response = await c_func.post(url=config["url"], headers=config["headers_x_post"], data=payload)
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}(), post) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}(), post failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)
    await asyncio.sleep(60)
    try:
        response = await c_func.get(url=response["data"]["links"]["self"], headers=config["headers_x_get"])
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}(), get) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}(), get failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)
    virustotal_note: str = ""
    for key in response["data"]["attributes"]["stats"].keys():
        virustotal_note += f' {key} stat: {response["data"]["attributes"]["stats"][key]}' * config[f"show_{key}"]

    from_dict_to_list: list[dict] = [response["data"]["attributes"]["results"][key] for key in
                                     response["data"]["attributes"]["results"].keys()]
    c = Counter([result["category"] for result in from_dict_to_list])
    virustotal_note += f' category from vendors: {str(c).replace("Counter", "")}' * config[
        f"show_category_from_vendors"]
    offense_note[name] = f'\n Da {Name}:[{virustotal_note}].'


async def pulsedive(config: dict, offense_note: dict[str, str], url: str) -> None:
    """
    ### Analyze url on Pulsedive

    Args:
        - `config`: config["Pulsedive"] expected
        - `offense_note`: dict for the offense's note
        - `url`: url to analyze
    """
    if not config["in_use"]:
        return

    name: str = "pulsedive"
    Name: str = "Pulsedive"

    params: dict = deepcopy(config["post_params"])
    params["value"] = url
    try:
        response = await c_func.post(url=config["url"], headers=config["headers"], data=params)
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}()) connection timeout')
        offense_note[name] = f"\n Da {Name}: error."
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}() failed), status code: {status}')
        offense_note[name] = f"\n Da {Name}: error."
        return
    assert isinstance(response, dict)
    await asyncio.sleep(60)
    params: dict = deepcopy(config["get_params"])
    params["qid"] = response["qid"]
    try:
        response = await c_func.get(url=config["url"], headers=config["headers"], params=params)
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}()) connection timeout')
        offense_note[name] = f"\n Da {Name}: error."
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}() failed), status code: {status}')
        offense_note[name] = f"\n Da {Name}: error."
        return
    assert isinstance(response, dict)
    pulsedive_note = f' Url risk: {response["data"]["risk"]}' * config["show_url_risk"]
    for key in response["data"]["links"].keys():
        c = Counter([url["risk"] for url in response["data"]["links"][key]])
        pulsedive_note += f' {key.lower()} risks: {str(c).replace("Counter", "")}' * config[
            f"show_{key.replace(' ', '')}"]

    offense_note[name] = f"\n Da {Name}:[{pulsedive_note}]."


async def criminalip(config: dict, offense_note: dict[str, str], ip: str) -> None:
    """
    ### Analyze ip on CriminalIp

    Args:
        - `config`: config["CriminalIp"] expected
        - `offense_note`: dict for the offense's note
        - `ip`: ip to analyze.
    """
    if not config["in_use"]:
        return

    name: str = "criminalip"
    Name: str = "CriminalIp"

    url = str(deepcopy(config["url"])).replace("%ip%", ip)

    try:
        response = await c_func.get(url=url, headers=config["headers"], params={})
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}()) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}() failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)
    if "ip" not in response:
        offense_note[name] = f'\n Da {Name}: ipV4 invalido.'
        return
    criminalip_note: str = f' ip: {response["ip"]}' * config["show_ip"]
    for key in response["tags"].keys():
        criminalip_note += f' {key.replace("is_", " ")}: {response["tags"][key]}' * config[f"show_{key}"]

    offense_note[name] = f'\n Da {Name}:[{criminalip_note}].'


async def criminalip_url(config: dict, offense_note: dict[str, str], url: str) -> None:
    """
    ### Analyze url on CriminalIp

    Args:
        - `config`: config["CriminalIp_url"] expected
        - `offense_note`: dict for the offense's note
        - `url`: url to analyze.
    """
    if not config["in_use"]:
        return

    name: str = "criminalip_url"
    Name: str = "CriminalIp_url"

    data: dict = {"query": url}
    try:
        response = await c_func.post(url=config["url_x_scan"], headers=config["headers"], data=data)
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}()) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}() failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)
    await asyncio.sleep(60)
    get_url = deepcopy(config["url_x_report"]).replace('%id%', str(response["data"]["scan_id"]))
    try:
        response = await c_func.get(url=get_url, headers=config["headers"], params={})
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}()) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}() failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)
    if "data" not in response:
        offense_note[name] = f'\n Da {Name}: url invalida.'
        return
    criminalip_url_note: str = f' url: {url}' * config["show_url"]
    for item in response["data"]["connected_ip_info"]:
        for key in item.keys():
            criminalip_url_note += f' {key}: {item[key]}' * config[f"show_{key}"]

    offense_note[name] = f'\n Da {Name}:[{criminalip_url_note}].'


async def google_safe_browsing(config: dict, offense_note: dict[str, str], url: str) -> None:
    """
    ### Analyze url on Google Safe Browsing

    Args:
        - `config`: config["Google_Safe_Browsing"] expected
        - `offense_note`: dict for the offense's note
        - `url`: url to analyze.
    """
    if not config["in_use"]:
        return

    name: str = "google_safe_browsing"
    Name: str = "Google_Safe_Browsing"

    gsb = SafeBrowsing(config["key"])
    response = gsb.lookup_urls([url])

    if not isinstance(response, dict):
        offense_note[name] = f'\n Da {Name.replace("_", " ")}: error.'
        return
    google_safe_browsing_note: str = ""
    for key in response[url].keys():
        google_safe_browsing_note += f" {key}: {str(response[url][key])}" * config[f"show_{key}"]

    offense_note[name] = f'\n Da {Name.replace("_", " ")}:[{google_safe_browsing_note}].'


async def ipregistry(config: dict, offense_note: dict[str, str], ip: str) -> None:
    """
    ### Analyze ip on IpRegistry

    Args:
        - `config`: config["IpRegistry"] expected
        - `offense_note`: dict for the offense's note
        - `ip`: ip to analyze.
    """
    if not config["in_use"]:
        return

    name: str = "ipregistry"
    Name: str = "IpRegistry"

    url = str(deepcopy(config["url"])).replace("%ip%", ip).replace("%key%", config["key"])
    try:
        response = await c_func.get(url=url, headers={})
    except ClientConnectorError:
        logger.error(f'{name} connection error ({name}()) connection timeout')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'{name} connection error ({name}() failed), status code: {status}')
        offense_note[name] = f'\n Da {Name}: error.'
        return
    assert isinstance(response, dict)
    ipregistry_note: str = ''
    for key in response["security"]:
        ipregistry_note += f' {key.replace("is_", "")}: {response["security"][key]}' * config[f"show_{key}"]
    offense_note[name] = f'\n Da {Name}:[{ipregistry_note}].'
