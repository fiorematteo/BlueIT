import time
import datetime
import json
from logging import Logger
import custom_logger as c_logger
import asyncio
import custom_func as c_func
import copy
import aiohttp
import custom_exceptions as c_execpt
from openpyxl import Workbook


logger: Logger = c_logger.my_logger(name="Reports")
local_dict: dict[str, str] = {
    "Questa offensiva è stata chiusa con motivo: ": "\n Note: ",
    "This offense was closed with reason: ": "\n Notes: ",
    }
config: dict = {}
wb: Workbook = Workbook()


def last_seven_days_filter(offense: dict) -> bool:
    # unix time used in milliseconds(unix time * 1000)
    t = time.localtime(time.time())
    date_time = datetime.datetime(t.tm_year, t.tm_mon, t.tm_mday, 9, 0)
    today = time.mktime(date_time.timetuple()) * 1000
    week_unix = 604800 * 1000
    return today - week_unix < offense["start_time"] and offense["start_time"] < today


async def get_weakly_offenses_list() -> list[dict]:
    api_url: str = "https://10.112.2.20/api/siem/offenses?fields=id%2C%20description%2C%20close_time%2C%20event_count%2C%20start_time%2C%20status%2C%20domain_id"
    headers: dict = copy.deepcopy(config["QRadar"]["headers"])
    counter: int = 0
    offenses_list: list = []
    while True:
        headers["Range"] = f"items={counter}00-{counter}99"
        response = await c_func.get(url=api_url, headers=headers, ssl=False)
        last_id: int = int(response[-1]["id"])
        offenses_list.extend(list(filter(last_seven_days_filter, response)))
        counter += 1
        if int(offenses_list[-1]["id"]) != last_id:
            break
    return offenses_list


async def get_cl_reason_and_cl_note(offense_close_time, notes_list: list[dict]) -> str:
    to_canc_note: dict = {}
    cl_note: str = ""
    cl_reason: str = ""
    for note_dict in notes_list:
        if not (offense_close_time < note_dict["create_time"] < offense_close_time + 1000):
            continue
        for key in local_dict.keys():
            if key in note_dict["note_text"]:
                cl_note: str = note_dict["note_text"].split(local_dict[key])[1]
                cl_reason: str = note_dict["note_text"].split(local_dict[key])[0].split(key)[1]
        to_canc_note = note_dict
    notes_list.pop(notes_list.index(to_canc_note))
    return f"{cl_reason} {cl_note}"


async def get_notes(offense: dict) -> dict:
    offense_id: int = offense["id"]
    api_url: str = f"https://10.112.2.20/api/siem/offenses/{offense_id}/notes?fields=create_time%2C%20note_text"
    headers: dict = config["QRadar"]["headers"]
    response = await c_func.get(url=api_url, headers=headers, ssl=False)
    notes_list: list[dict] = response
    if "CLOSED" in offense["status"]:
        offense["cl_reason+note"] = await get_cl_reason_and_cl_note(offense["close_time"], notes_list)
    if not notes_list:
        offense["note"] = ""
        return offense
    control: int = 0
    for note in notes_list:
        if note["create_time"] > control:
            offense["note"] = note["note_text"].replace("\n", "").replace("\r", "")
            control = note["create_time"]
    return offense


async def weakly_dump(offenses_list: list[dict], domain_id: int) -> None:
    domain_name: str = config["QRadar"]["domain_id"][domain_id]
    show_dt: bool = config["QRadar"]["DarkTrace"][domain_name]
    show_sophos: bool = config["QRadar"]["Sophos"][domain_name]
    counter: int = 0
    dt_counter: int = 0
    sophos_counter: int = 0
    output_txt: list[str] = []
    output_xlsx: list[list] = []
    special_case_list: list[str] = []
    ws = wb.active
    for offense in offenses_list:
        if (offense["domain_id"] != int(domain_id)) or ("HIDDEN" in offense["status"]):
            continue
        if "DT" in offense["description"] or "Darktrace" in offense["description"]:
            dt_counter += 1
        if "SCC" in offense["description"]:
            sophos_counter += 1
        counter += 1
        offense_start_time = datetime.datetime.fromtimestamp(int(int(offense["start_time"])/1000))
        special_case: bool = False
        for key in config["QRadar"]["special_cases"].keys():
            if key in offense["description"]:
                special_case_list.append(f'{offense["id"]}\n{config["QRadar"]["special_cases"][key].replace("$event_count$ ", str(offense["event_count"]))}\n\n')
                special_case = True
        if "OPEN" in offense["status"] and not special_case:
            output_txt.append(f'{offense["id"]} {offense_start_time}\n{offense["note"]}\n\n')
            output_xlsx.append([offense["id"], offense["note"]])
    counters = f"Allarmi totali: {counter}\n" + f"Breach alert di Darktrace: {dt_counter}\n" * show_dt + f"Allarmi di Sophos: {sophos_counter}\n" * show_sophos + f"Offense di QRadar: {counter - (dt_counter + sophos_counter)}\n\n"
    output_txt.insert(0, counters)
    output_txt.insert(0, f"Buongiorno,\ndi seguito le informazioni sulla gestione degli eventi del turno H8.\n\n")
    output_txt.extend(special_case_list)
    with open(f'../dump_{domain_name}.txt', "w", encoding="utf-8") as file:
        file.writelines(output_txt)
    for row in output_xlsx:
        ws.append(row)
        ws.append(["", "Risoluzione"])
    t = time.localtime(time.time())
    wb.save(f'D:\Onedrive\OneDrive - BLUEIT SPA\⍼ Report x Stefano\{t.tm_year}-{t.tm_mon}-{t.tm_mday} {domain_name}.xlsx')


async def weakly_report() -> None:
    print("Fetching offenses")
    try:
        lista_offense: list[dict] = await get_weakly_offenses_list()
    except aiohttp.ClientConnectorError:
        logger.critical(f'QRadar connection timeout (get_weakly_offenses_list() failed)')
        print(f"QRadar connection timeout")
        return
    except c_execpt.ConnectionStatusError as status:
        logger.error(f'QRadar connection error (get_weakly_offenses_list() failed), status code: {status}')
        print(f"QRadar connection error, status code: {status}")
        return

    offenses_to_rm: list[int] = []
    for offense in lista_offense:
        print(f"Fetching {offense['id']}'s notes")
        try:
            await get_notes(offense)
        except aiohttp.ClientConnectorError:
            logger.critical(f'QRadar connection timeout (get_notes() failed)')
            print(f"QRadar connection timeout")
        except c_execpt.ConnectionStatusError as status:
            logger.error(f'QRadar connection error (get_notes() failed), status code: {status}')
            print(f"QRadar connection error, status code: {status}")
        if "CLOSED" in offense["status"] and "Test di rule use case" in offense["cl_reason+note"]:
            offenses_to_rm.insert(0, lista_offense.index(offense))

    for num in offenses_to_rm:
        lista_offense.pop(num)

    for domain_id in config["QRadar"]["domain_id"].keys():
        loop.create_task(weakly_dump(lista_offense, domain_id))
    print("Done\n")


async def main() -> None:
    global config
    with open("config.json", "r", encoding="UTF-8") as file:
        config = json.loads(file.read())
    print("Weakly report start")
    await weakly_report()
    print("Weakly report end")

if __name__ == "__main__":
    loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(main())
    except FileNotFoundError:
        logger.critical('file "config.json" not found')
        print("File config non trovato")
