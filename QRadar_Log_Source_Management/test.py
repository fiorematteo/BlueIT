
if __name__ == "__main__":
	header: dict = {
		"name": "none",
		"none": "name"
		}
	print(header)
	header.update({
		"main": "lol",
		"MANE": "LOL"
		})
	print(header)
