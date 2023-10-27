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
                             google_safe_browsing(config["Google_Safe_Browsing"], offense_note, url)
                             )
        return
    await asyncio.gather(urlscan(config["UrlScan"], offense_note, url),
                         virustotal(config["VirusTotal"], offense_note, url),
                         abuseip(config["AbuseIp"], offense_note, ip),
                         pulsedive(config["Pulsedive"], offense_note, url),
                         criminalip(config["CriminalIp"], offense_note, ip),
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
    data: dict[str, str] = {"url": f"http://{url}/", "visibility": "public"}
    try:
        response = await c_func.post(url=config["url"], headers=config["headers"], data=json.dumps(data))
    except ClientConnectorError:
        logger.error('urlscan connection error (urlscan(), post) connection timeout')
        offense_note["urlscan"] = f'\n Da UrlScan: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'urlscan connection error (urlscan(), post failed), status code: {status}')
        offense_note["urlscan"] = f'\n Da UrlScan: error.'
        return
    assert isinstance(response, dict)
    await asyncio.sleep(60)
    try:
        response = await c_func.get(url=response["api"], headers=config["headers"])
    except ClientConnectorError:
        logger.error('urlscan connection error (urlscan(), get) connection timeout')
        offense_note["urlscan"] = f'\n Da UrlScan: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'urlscan connection error (urlscan(), get failed), status code: {status}')
        offense_note["urlscan"] = f'\n Da UrlScan: error.'
        return
    assert isinstance(response, dict)

    urlscan_note: str = ""
    is_malicious_list: list = []
    for key in response["verdicts"].keys():
        urlscan_note += f' {key} score: {response["verdicts"][key]["score"]}' * config[f"show_{key}_score"]
        is_malicious_list.append(response["verdicts"][key]["malicious"])
    c = Counter(is_malicious_list)
    urlscan_note += f' malicious counter: {str(c).replace("Counter", "")}' * config["show_malicious_counter"]
    offense_note["urlscan"] = f'\n Da UrlScan:[{urlscan_note}].'


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
    offense_note["abuseip"] = ""

    querystring: dict[str, str] = {
        'ipAddress': ip,
        'maxAgeInDays': config["maxAgeInDays_of_ip_reports"]
        }
    try:
        response = await c_func.get(url=config["url"], headers=config["headers"], params=querystring)
    except ClientConnectorError:
        logger.error('abuseip connection error (abuseip()) connection timeout')
        offense_note["abuseip"] = f'\n Da AbuseIp: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'abuseip connection error (abuseip() failed), status code: {status}')
        offense_note["abuseip"] = f'\n Da AbuseIp: error.'
        return
    assert isinstance(response, dict)
    abuseip_note: str = ""
    for key in response["data"].keys():
        key_x_note = await c_func.string_spacer(key)
        abuseip_note += f' {key_x_note.lower().replace("is ", "")}: {response["data"][key]}' * config[f"show_{key}"]

    offense_note["abuseip"] = f'\n Da AbuseIp:[{abuseip_note}].'


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
    offense_note["virustotal"] = ""
    payload: str = f"url={url}"
    try:
        response = await c_func.post(url=config["url"], headers=config["headers_x_post"], data=payload)
    except ClientConnectorError:
        logger.error('virustotal connection error (virustotal(), post) connection timeout')
        offense_note["virustotal"] = f'\n Da VirusTotal: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'virustotal connection error (virustotal(), post failed), status code: {status}')
        offense_note["virustotal"] = f'\n Da VirusTotal: error.'
        return
    assert isinstance(response, dict)
    # print(response["data"]["id"])
    # print(response["data"]["links"]["self"])
    await asyncio.sleep(60)
    try:
        response = await c_func.get(url=response["data"]["links"]["self"], headers=config["headers_x_get"])
    except ClientConnectorError:
        logger.error('virustotal connection error (virustotal(), get) connection timeout')
        offense_note["virustotal"] = f'\n Da VirusTotal: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'virustotal connection error (virustotal(), get failed), status code: {status}')
        offense_note["virustotal"] = f'\n Da VirusTotal: error.'
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
    offense_note["virustotal"] = f'\n Da VirusTotal:[{virustotal_note}].'


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
    params: dict = deepcopy(config["post_params"])
    params["value"] = url
    try:
        response = await c_func.post(url=config["url"], headers=config["headers"], data=params)
    except ClientConnectorError:
        logger.error('pulsedive connection error (pulsedive()) connection timeout')
        offense_note["pulsedive"] = f"\n Da Pulsedive: error."
        return
    except ConnectionStatusError as status:
        logger.error(f'pulsedive connection error (pulsedive() failed), status code: {status}')
        offense_note["pulsedive"] = f"\n Da Pulsedive: error."
        return
    assert isinstance(response, dict)
    await asyncio.sleep(60)
    params: dict = deepcopy(config["get_params"])
    params["qid"] = response["qid"]
    try:
        response = await c_func.get(url=config["url"], headers=config["headers"], params=params)
    except ClientConnectorError:
        logger.error('pulsedive connection error (pulsedive()) connection timeout')
        offense_note["pulsedive"] = f"\n Da Pulsedive: error."
        return
    except ConnectionStatusError as status:
        logger.error(f'pulsedive connection error (pulsedive() failed), status code: {status}')
        offense_note["pulsedive"] = f"\n Da Pulsedive: error."
        return
    assert isinstance(response, dict)
    pulsedive_note = f' Url risk: {response["data"]["risk"]}' * config["show_url_risk"]
    for key in response["data"]["links"].keys():
        c = Counter([url["risk"] for url in response["data"]["links"][key]])
        pulsedive_note += f' {key.lower()} risks: {str(c).replace("Counter", "")}' * config[
            f"show_{key.replace(' ', '')}"]

    offense_note["pulsedive"] = f"\n Da Pulsedive:[{pulsedive_note}]."


async def criminalip(config: dict, offense_note: dict[str, str], ip: str) -> None:
    """
    ### Analyze ip on criminalip

    Args:
        - `config`: config["CriminalIp"] expected
        - `offense_note`: dict for the offense's note
        - `ip`: ip to analyze.
    """
    if not config["in_use"]:
        return
    offense_note["criminalip"] = ""
    url = str(deepcopy(config["url"])).replace("%ip%", ip)

    try:
        response = await c_func.get(url=url, headers=config["headers"], params={})
    except ClientConnectorError:
        logger.error('criminalip connection error (criminalip()) connection timeout')
        offense_note["criminalip"] = f'\n Da CriminalIp: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'criminalip connection error (criminalip() failed), status code: {status}')
        offense_note["criminalip"] = f'\n Da CriminalIp: error.'
        return
    assert isinstance(response, dict)
    if "ip" not in response:
        offense_note["criminalip"] = f'\n Da CriminalIp: ip invalido.'
        return
    criminalip_note: str = f' ip: {response["ip"]}' * config["show_ip"]
    for key in response["tags"].keys():
        criminalip_note += f' {key.replace("is_", " ")}: {response["tags"][key]}' * config[f"show_{key}"]

    offense_note["criminalip"] = f'\n Da CriminalIp:[{criminalip_note}].'


async def google_safe_browsing(config: dict, offense_note: dict[str, str], url: str) -> None:
    offense_note["google_safe_browsing"] = f'\n Da Google Safe Browsing: error.'
    if not config["in_use"]:
        return
    gsb = SafeBrowsing(config["key"])
    response: dict = gsb.lookup_urls([url])  # type: ignore
    assert isinstance(response, dict)
    google_safe_browsing_note: str = ""
    for key in response[url].keys():
        google_safe_browsing_note += f" {key}: {str(response[url][key])}" * config[f"show_{key}"]

    offense_note["google_safe_browsing"] = f'\n Da Google Safe Browsing:[{google_safe_browsing_note}].'


async def ipregistry(config: dict, offense_note: dict[str, str], ip: str) -> None:
    """
    ### Analyze ip on ipregistry

    Args:
        - `config`: config["IpRegistry"] expected
        - `offense_note`: dict for the offense's note
        - `ip`: ip to analyze.
    """
    if not config["in_use"]:
        return
    offense_note["ipregistry"] = ""
    url = str(deepcopy(config["url"])).replace("%ip%", ip).replace("%key%", config["key"])

    try:
        response = await c_func.get(url=url, headers={})
    except ClientConnectorError:
        logger.error('ipregistry connection error (ipregistry()) connection timeout')
        offense_note["ipregistry"] = f'\n Da IpRegistry: error.'
        return
    except ConnectionStatusError as status:
        logger.error(f'ipregistry connection error (ipregistry() failed), status code: {status}')
        offense_note["ipregistry"] = f'\n Da IpRegistry: error.'
        return
    assert isinstance(response, dict)
    ipregistry_note: str = ''
    for key in response["security"]:
        ipregistry_note += f' {key.replace("is_", "")}: {response["security"][key]}' * config[f"show_{key}"]
    offense_note["ipregistry"] = f'\n Da IpRegistry:[{ipregistry_note}].'
