import requests

url = "https://api.macvendors.com/f6:c8:9f:86:bc:d3"

payload = {}
headers = {
  'Cookie': '__cf_bm=_0JcK4vSN5NO86fZO7wNEn4VsYW49fFj3MShB_CzP48-1761821605-1.0.1.1-lQfyPLMbt1BUVHaxE.XqP12xaLQNcrEjjSmvwWQzdV8VjNZ6GHgtC7fjaC0_q4nKaHGV5xS4DwVTRKU7FABvb3oskZqjZa59LESxCuLtuNA'
}

response = requests.request("GET", url, headers=headers, data=payload)

print(response.text)
