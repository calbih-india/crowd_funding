import base64
import requests
import json


email = 'maulik@aptagrim.com'
password = 'abcd.1234'


url="http://127.0.0.1:8000/api/login/"
headers = {'content-type': 'application/json'}


body =  """{"email":\""""+email+"""\","password":\""""+ password+"""\"}"""

response = requests.get(url,data=body,headers=headers)
print(response.text)
resp =json.loads(response.text)
print(response.text)
