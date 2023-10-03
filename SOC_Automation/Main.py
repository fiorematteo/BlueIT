import asyncio
from logging import Logger
import argparse
from aioconsole import AsynchronousCli
from collections import Counter
from pymsteams import async_connectorcard
import time
import datetime
import custom_logger as c_logger
import QRadar
import custom_func as c_func


logger: Logger = c_logger.my_logger(name="SOC_Automation")
config: dict = {}
f_u: bool = True


async def teams_message(title: str, text: str) -> None:
    """
    ### Send message on MS Teams

    Args:
        - `title`: Title of the card send to MS Teams
        - `text`: Text of the card send to MS Teams
    """
    my_teams_message: async_connectorcard = async_connectorcard(config["MSTeams"]["connectorcard"])
    # my_teams_message: async_connectorcard = async_connectorcard(config["MSTeams"]["test_connectorcard"])
    my_teams_message.title(title)
    my_teams_message.text(text)
    loop.create_task(my_teams_message.send())


def filter_non_workable(offense: dict[str, str]) -> bool:
    """
    ### Filter out offenses

    Offenses that should not be worked on are either already assigned or older than 120 seconds

    Args:
        - `offense`: offense's dictionary containing all info about one

    Returns:
        - `bool`: True to be kept, False not to be kept
    """
    t = time.localtime(time.time())
    date_time = datetime.datetime(t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
    today = int(time.mktime(date_time.timetuple())) * 1000
    return not offense["assigned_to"] and ((today - int(offense["start_time"])) < 120 * 1000)


async def start_async_cli() -> None:
    """
    ### Starts the asynchronous CLI

    The asynchronous CLI for SOC_Automation
    """
    parser1 = argparse.ArgumentParser(description="Check task status.")
    parser2 = argparse.ArgumentParser(description="Close program.")
    parser3 = argparse.ArgumentParser(description="Reload new config file while running.")

    cli = AsynchronousCli({"task": (task_done, parser1),
                           "close": (very_cool_exit, parser2),
                           "newconf": (reload_config_file, parser3)}, prog="SOC_Automation")
    loop.create_task(cli.interact())


async def task_done(reader, writer) -> None:
    """
    ### Give bool counter of all task.done()

    Count how many task are active by counting how many are not finished.
    """
    c = Counter([task.done() for task in asyncio.all_tasks()])
    writer.write(f'task.done(): {str(c).replace("Counter", "")}\n')


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
    """
    ### Where the magic happens
    """
    global config
    config = await c_func.read_json()
    seconds_of_sleep: int = int(config["SOC_Automation"]["seconds_of_sleep"])

    await start_async_cli()

    user_id: int = 0
    while f_u:
        t = time.localtime(time.time())
        if t.tm_hour == 4 and t.tm_min == 0 and t.tm_sec < 30:
            loop.create_task(QRadar.import_txt_list(config["QRadar"], config["txt_ip_list"]))
        lista_offense: list[dict] = await QRadar.get_last_20_offenses(config["QRadar"])
        if not lista_offense:
            loop.create_task(teams_message(title="Console QRadar", text="get_last_20_offenses() did not work"))
            await asyncio.sleep((seconds_of_sleep/3))
            continue
        lista_offense = list(filter(filter_non_workable, lista_offense))
        if not lista_offense:
            await asyncio.sleep(seconds_of_sleep)
            continue
        teams_text: str = f""
        for offense in lista_offense:
            match offense:
                case offense if offense["severity"] >= int(config["QRadar"]["severity"]) and offense["offense_source"] in config["QRadar"]["log_sources_list"]:
                    user: str = config["QRadar"]["user_list"][user_id]
                    loop.create_task(QRadar.qradar_user_assignment(config["QRadar"], offense, user))
                    loop.create_task(QRadar.offense_process(config, offense))
                    teams_text += f"Offensiva {offense['id']} assegnata a: {user}\n\n"
                    user_id = (user_id + 1) * (user_id < len(config["QRadar"]["user_list"]) - 1)

                case {"severity": severity} if severity >= int(config["QRadar"]["severity"]):
                    loop.create_task(QRadar.offense_process(config, offense))
                    teams_text += f"Offensiva {offense['id']} alta severity\n"

                case _:
                    user: str = config["QRadar"]["user_list"][user_id]
                    loop.create_task(QRadar.qradar_user_assignment(config["QRadar"], offense, user))
                    loop.create_task(QRadar.offense_process(config, offense))
                    teams_text += f"Offensiva {offense['id']} assegnata a: {user}\n"
                    user_id = (user_id + 1) * (user_id < len(config["QRadar"]["user_list"]) - 1)
        loop.create_task(teams_message(title="Console QRadar", text=teams_text))
        await asyncio.sleep(seconds_of_sleep)

    print("Waiting for all task to finish\n")
    c = Counter([task.done() for task in asyncio.all_tasks()])
    task_not_done: bool = bool(c[False] - 2)
    # main() and AsynchronousCli() do count as unfinished tasks but should not be waited to finish, therefore -2
    while task_not_done:
        await asyncio.sleep(seconds_of_sleep)
        c = Counter([task.done() for task in asyncio.all_tasks()])
        task_not_done = bool(c[False] - 2)
        print(f"{'.' * int(seconds_of_sleep / 10)}")

    print("Exiting program\n")


if __name__ == '__main__':
    loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(main())
    except FileNotFoundError:
        logger.error("config.json not found")
        print("Config file not found\n")
    except KeyboardInterrupt:
        logger.info("keyboard interrupt")
        print("End\n")
    loop.close()
