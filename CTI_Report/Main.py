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
hostname: dict[str, str] = {"68.219.221.234": "LINCOUNTERAZU01",
                            "52.178.216.64": "LINNESSAZU",
                            "52.138.199.230": "WINSQLAZU01",
                            "52.138.140.97": "LINDTRACEAZU01",
                            "40.85.85.230": "WallixAccessManager",
                            "40.85.100.188": "WINTKAZUDB",
                            "40.69.76.127": "Wallix1",
                            "40.69.20.163": "WINSQLAZU02",
                            "40.113.72.137": "WinADFSProxy02",
                            "168.63.61.46": "WinADFSProxy01",
                            "137.116.247.117": "LINSHOPAZU",
                            "13.79.163.108": "WINSAPFIN03",
                            "13.79.162.51": "WINSAPFIN02",
                            "13.79.161.162": "WINTKAZUAS-TEST",
                            "13.79.152.123": "WINSAPFIN04",
                            "13.74.29.116": "WINXATLASAZU01",
                            "13.74.249.17": "tms-poller",
                            "13.74.223.51": "WINSAPFIN01B",
                            "13.74.180.87": "WINPITAZUAS",
                            "13.74.175.38": "WINDFSAZU01",
                            "13.74.156.36": "WINFTPAZU01",
                            "104.45.82.56": "WINTKAZUAS",
							"18.198.137.182": "cn.acmilan.com",
							"18.198.137.183": "acmilan.com",
							"18.198.137.184": "cn-test.acmilan.com",
							"35.157.174.232": "commercial.acmilan.com",
							"35.157.174.233": "landing.acmilan.com",
							"35.157.174.234": "marketing.acmilan.com",
							"18.193.195.205": "casamilan.acmilan.com",
							"18.194.143.27": "pre-prod.acmilan.com",
							"3.69.75.170": "pre-prod.acmilan.com",
							"18.157.59.186": "pre-prod.acmilan.com",
							"13.225.63.28": "newplayerunlocked.acmilan.com",
							"13.225.63.86": "newplayerunlocked.acmilan.com",
							"13.225.63.99": "newplayerunlocked.acmilan.com",
							"13.225.63.58": "newplayerunlocked.acmilan.com",
							"13.225.223.13": "derbytogether.acmilan.com",
							"13.225.223.88": "derbytogether.acmilan.com",
							"13.225.223.5": "derbytogether.acmilan.com",
							"13.225.223.122": "derbytogether.acmilan.com",
							"18.164.96.30": "www.acmilan.com",
							"18.164.96.21": "www.acmilan.com",
							"18.164.96.13": "www.acmilan.com",
							"18.164.96.77": "www.acmilan.com",
							"18.164.96.13": "m.acmilan.com",
							"18.164.96.21": "m.acmilan.com",
							"18.164.96.77": "m.acmilan.com",
							"18.164.96.30": "m.acmilan.com",
							"185.3.93.228": "s126334._domainkey.acmilan.com",
							"170.187.131.209 ": "s126334._domainkey.acmilan.com",
							"172.104.159.192": "backofficehospitality.acmilan.com",
							"172.104.210.190": "matchprogram.acmilan.com",
							"185.3.93.228": "em126334.acmilan.com",
							"170.187.131.209": "em126334.acmilan.com",
							"40.113.72.137": "adfs.acmilan.com",
							"52.98.206.223": "autodiscover.acmilan.com",
							"52.98.206.176": "autodiscover.acmilan.com",
							"13.74.156.36": "ftp.acmilan.com",
							"68.219.221.234": "counter.acmilan.com",
							"137.116.247.117": "shopify.acmilan.com",
							"52.112.67.51": "sip.acmilan.com",
							"40.126.32.0/24": "msoid.acmilan.com",
							"52.112.64.14": "lyncdiscover.acmilan.com",
							"20.107.224.27": "tickettest.acmilan.com",
							"2.228.65.179": "backoffice.acmilan.com",
							"86.107.32.68": "club1899.acmilan.com",
							"86.107.32.69": "hospitality.acmilan.com",
							"160.8.15.172": "identity-dev.acmilan.com",
							"160.8.248.44": "identity-dev.acmilan.com",
							"160.8.15.44": "identity-dev.acmilan.com",
							"13.109.180.5": "help.acmilan.com",
							"161.71.33.242": "email.acmilan.com",
							"161.71.82.45": "click.email.acmilan.com",
							"161.71.80.207": "cloud.email.acmilan.com",
							"161.71.35.201": "mta.email.acmilan.com",
							"161.71.84.43": "view.email.acmilan.com",
							"45.60.77.169": "corporate-dev.acmilan.com",
							"45.60.77.170": "corporate.acmilan.com",
							"45.60.77.171": "tickets-dev.acmilan.com",
							"45.60.77.172": "tickets.acmilan.com",
							"217.29.164.91": "mtmthumb.acmilan.com",
							"151.1.220.33": "www.cuorerossonero.acmilan.com",
							"46.252.147.38": "xmas.acmilan.com",
							"89.40.175.238": "hospitality2021.acmilan.com",
							"193.42.201.75": "mail.logisticacrn.acmilan.com",
							"185.34.84.187": "cs.milan.acmilan.com",
							"185.34.84.120": "lm.milan.acmilan.com",
							"185.34.84.144": "t.milan.acmilan.com",
							"50.7.24.82": "mp.acmilan.com",
							"194.177.120.23": "admin.museum.acmilan.com",
							"194.177.120.24": "inside.museum.acmilan.com",
							"83.221.113.178": "payment.acmilan.com",
							"116.203.50.115": "qr.acmilan.com",
							"23.227.38.74": "store.acmilan.com",
							"23.227.38.75": "www.store.acmilan.com",
							"104.22.58.235": "singletickets.acmilan.com",
							"104.22.59.235": "singletickets.acmilan.com",
							"172.67.25.205": "singletickets.acmilan.com",
							"20.107.224.27": "abbonamenti.acmilan.com"
                            }


def ip_sort(item: list):
	ip = item[0]
	num = int(ip.split(".")[0]) * 1000000 + int(ip.split(".")[1]) * 10000 + int(ip.split(".")[2]) * 100 + int(ip.split(".")[3].split(" ")[0])
	return num


async def main() -> None:
	"""
	### Where the magic happens
	"""

	global export
	export = await c_func.read_json(f"{file_path + file_name}.json")
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
