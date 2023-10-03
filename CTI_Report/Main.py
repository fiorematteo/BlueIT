import asyncio
from logging import Logger
import custom_logger as c_logger
import custom_func as c_func
from openpyxl import Workbook
import os

file_name: str = "export"

logger: Logger = c_logger.my_logger(name="CTI_Report")
export: list = []
file_path: str = f"C:\\Users\\{os.getlogin()}\\Downloads\\"
wb: Workbook = Workbook()
hostname: dict = {}


def ip_sort(item: list):
	ip = item[0]
	num = int(ip.split(".")[0]) * 1000000 + int(ip.split(".")[1]) * 10000 + int(ip.split(".")[2]) * 100 + int(ip.split(".")[3].split(" ")[0])
	return num


async def main() -> None:
	"""
	### Where the magic happens
	"""

	global export, hostname
	export = await c_func.read_json(f"{file_path + file_name}.json")
	hostname = await c_func.read_json("hostname.json")
	ws = wb.active
	ws.append(["IP (hostname)", "Port"])
	export_xlsx: list[list] = []

	for event in export:
		match event["event_type"]:
			case "Open TCP Port":
				ip = f'{event["data"].split(":")[0]}'
				port = int(event["data"].split(":")[1])
				if ip in hostname.keys():
					ip += f" ({hostname[ip]})"
				export_xlsx.append([ip, port])

			case "Open TCP Port Banner":
				ip = f'{event["source_data"].split(":")[0]}'
				port = int(event["source_data"].split(":")[1])
				if ip in hostname.keys():
					ip += f" ({hostname[ip]})"
				export_xlsx.append([ip, port])

			case _:
				pass

	export_xlsx.sort(key=ip_sort)
	for item in export_xlsx:
		ws.append(item)
	wb.save(f'{file_path}Report Surface Attack.xlsx')


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
