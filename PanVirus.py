import requests
import json
import time
import os
import hashlib

def check(file):
    with open(file,"rb") as f:
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
    return readable_hash

def postfile(fname,apikey):
    posturl = "https://www.virustotal.com/api/v3/files/"

    fileqwe = "files/" + fname

    headers = {'accept': 'application/json', 'x-apikey': apikey}
    files = {'file': (fileqwe, open(fileqwe, 'rb'))}
    global hashid
    hashid = check(fileqwe)

    requests.post(posturl, files=files, headers=headers)

def getreport(fname,apikey):
    apiurl = "https://www.virustotal.com/api/v3/files/" + hashid

    headers = {"accept": "application/json","x-apikey": apikey}
    response = requests.get(apiurl, headers=headers)
    result = json.loads(response.text)["data"]

    attributes = result["attributes"]
    gen_rslt = attributes["last_analysis_stats"]
    antis = attributes["last_analysis_results"]

    os.system("cls")

    codesha256 = result["id"]
    filename = attributes["meaningful_name"]
    size = attributes["size"]
    red_state = gen_rslt["malicious"]
    yellow_state = gen_rslt["suspicious"]
    green_state = gen_rslt["undetected"]

    with open(f"reports/RAPOR-({fname}).txt","w",encoding="utf-8") as wrtfile:
        
        wrtfile.write("="*45 + " SCAN REPORT " + "="*45 + "\n")
        wrtfile.write(f"DOSYA ADI: {filename}\n")
        wrtfile.write(f"DOSYA IMZASI: {codesha256}\n")
        wrtfile.write(f"DOSYA BOYUTU: {size}\n")
        wrtfile.write(f"TEHLIKELI DURUM SAYISI: {red_state}\n")
        wrtfile.write(f"RISKLI DURUM SAYISI: {yellow_state}\n")
        wrtfile.write(f"TEMIZ DURUM SAYISI: {green_state}\n")

        for k, v in antis.items():
            antiname = v["engine_name"]
            version = v["engine_version"]
            category = v["category"]
            anti_result = v["result"]
            wrtfile.write("-"*45 + "\n")
            wrtfile.write(f"ANTIVIRUS ADI: {antiname}\n")
            wrtfile.write(f"ANTIVIRUS VERSIYONU: {version}\n")
            wrtfile.write(f"DURUM KATEGORISI: {category}\n")
            wrtfile.write(f"SONUÇ: {anti_result}\n\n")
        
try:
    apikey = "" # API KEY

    os.system("cls")
    print("="*15 + " PanVirus Antivirus " + "="*15 )
    print("Taratacağınız dosyayı files klasörüne taşıyın..")

    fname = input("Lütfen taratılacak dosyanın adını giriniz : ")

    postfile(fname,apikey)

    print("Virus taraması sonuçları 1 dakika içerisinde reports dizininde olacaktır.")
    time.sleep(3)
    os.system("cls")

    a = 1
    b = "="
    c = ">"
    dosya = "Lütfen Bekleyin... "

    while True:
        a += 1
        print(dosya+b*a+c)
        time.sleep(0.5)
        os.system("cls")
        if a == 90:
            break

    getreport(fname,apikey)

except Exception as e:
    print(f"Bir hata oluştu. {e}")
    
else:
    print("Tarama işlemi tamamlandı.\nTarama raporunu reports klasöründe bulabilirsiniz.")