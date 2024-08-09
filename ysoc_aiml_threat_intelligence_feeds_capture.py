
from ysoc_aiml_threat_intelligence_imports import requests

# url = "https://ics-ap-apis.p.rapidapi.com/advisory/latest"
# querystring = {"n": "3"}
url = "https://ics-ap-apis.p.rapidapi.com/advisory/pv"
querystring = {"vendor": "Siemens", "product": "SIMATIC S7-400 CPU"}


headers = {
    "x-rapidapi-key": "a7684b29b5msha29c6f5ddac1bcdp16b027jsn4eaa1d88bcfe",
    "x-rapidapi-host": "ics-ap-apis.p.rapidapi.com"
}

response = requests.get(url, headers=headers, params=querystring)

print(response.json())
