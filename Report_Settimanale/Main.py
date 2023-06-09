from openpyxl import Workbook

wb: Workbook = Workbook()
ws = wb.active
ws.append([1, 2])
ws.append(["", 3, 4])
wb.save("sample.xlsx")
