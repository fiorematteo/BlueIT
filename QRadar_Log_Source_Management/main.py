import asyncio
from logging import Logger
import custom_logger as c_logger
import argparse
from aioconsole import AsynchronousCli
import pymsteams
import time
import datetime
import custom_func as c_func
from copy import deepcopy
from custom_exceptions import ConnectionStatusError
from aiohttp import ClientConnectorError


logger: Logger = c_logger.my_logger(name="LS Management")
config: dict = {}
f_u: bool = True


async def teams_message(title: str, text: str) -> None:
    """
    ### Send message on MS Teams

    Args:
        - `title`: Title of the card send to MS Teams
        - `text`: Text of the card send to MS Teams
    """
    my_teams_message: pymsteams.async_connectorcard = pymsteams.async_connectorcard(config["MSTeams"]["connectorcard"])
    # teamsTestMessage: pymsteams.async_connectorcard = pymsteams.async_connectorcard(config["MSTeams"]["test_connectorcard"])
    my_teams_message.title(title)
    my_teams_message.text(text)
    loop.create_task(my_teams_message.send())


async def start_async_cli() -> None:
    """
    ### Starts the asynchronous CLI

    The asynchronous CLI for SOC_Automation
    """
    parser2 = argparse.ArgumentParser(description="Close program.")
    parser3 = argparse.ArgumentParser(description="Reload new config file while running.")

    cli = AsynchronousCli({"close": (very_cool_exit, parser2),
                           "newconf": (reload_config_file, parser3)}, prog="SOC_Automation"
                          )
    loop.create_task(cli.interact())


async def very_cool_exit(reader, writer) -> None:
    """
    ### Gracefully end the program

    Exit the first while in main.
    """
    global f_u
    f_u = False


async def reload_config_file(reader, writer) -> None:
    """
    ### Load new config file

    While the program is running load the config file.
    """
    global config
    try:
        config = await c_func.read_json()
    except FileNotFoundError:
        logger.info("new config.json not found")
        print("Config file not found. Keeping old one\n")
        return
    print("New config file loaded\n")


async def main() -> None:
    await start_async_cli()
    global config
    config = await c_func.read_json()

    while True:
        seconds_of_sleep: int = int(deepcopy(config["LS_Management"]["minute_of_sleep"])) * 60
        try:
            ls_list: list[dict] = await c_func.get(url=config["QRadar"]["server_url"] + config["QRadar"]["url_x_log_sources"],
                                                   headers=config["QRadar"]["headers"],
                                                   ssl=False)
        except ClientConnectorError:
            logger.error('main connection error (main(), get) connection timeout')
            await asyncio.sleep(seconds_of_sleep / 3)
            continue
        except ConnectionStatusError as status:
            logger.error(f'main connection error (main(), get failed), status code: {status}')
            await asyncio.sleep(seconds_of_sleep / 3)
            continue
        ls_id_list: list[str] = config["QRadar"]["ls_id_list"]
        ls_id_list.sort()
        ls_inactive: str = ""
        t = time.localtime(time.time())
        date_time = datetime.datetime(t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        today: int = int(time.mktime(date_time.timetuple()) * 1000)
        minute_of_inactivity: int = int(config["QRadar"]["minute_of_inactivity"]) * 60 * 1000
        for ls in ls_list:
            if ls["id"] not in ls_id_list:
                continue
            if today - int(ls["last_event_time"]) > minute_of_inactivity:
                ls_inactive += f'{ls["name"]}\n'
            if ls["id"] == ls_id_list[-1]:
                break
        await teams_message(title="Inactive Log Sources", text=ls_inactive)
        await asyncio.sleep(seconds_of_sleep)


if __name__ == '__main__':
    loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(main())
    except FileNotFoundError:
        logger.error("config.json not found")
        print("Config file not found\n")
    loop.close()
