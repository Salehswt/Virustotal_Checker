AUTHOR = 'Saleh - Haboob Team'
VERSION = "0.1"
import os
import requests
import sys
import datetime
import csv
import hashlib
import argparse
import re
from dotenv import load_dotenv
import time
from prettytable import PrettyTable
from colorama import init
init(convert=True)

VT_URL = "https://www.virustotal.com/api/v3/"
load_dotenv('.env')
apikey = os.getenv('apikey')

headers = {
         "Accept": "application/json",
         "x-apikey": apikey 
         }

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREY  = '\33[90m'
    ENDC = '\033[0m'

# Download the file by the hash; it requires a premium API key.
def DownloadFile(hash):
    file_hash = hash
    url = VT_URL + 'files/' + file_hash + '/download'
  
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
         pass
    
    else:
         resp = response.json()
         print (Colors.RED + str(resp.get('error').get('message')) + Colors.ENDC)
         exit()

    name= "VTexecutable.infected"
    with open(name, 'wb') as f:
         f.write(response.content)
    print(Colors.GREEN + "Done downloading! The name of the file is: " + name +  Colors.ENDC)

# This function takes a single hash and returns a list of engines that flagged the hash.

def Check_hash(hash):  
        hash = hash
        info_url = VT_URL + "files/" + hash 
        res = requests.get(info_url ,headers = headers)
        if res.status_code == 200:
            result = res.json()
            last_update = datetime.datetime.fromtimestamp(result.get("data").get("attributes").get("last_modification_date"))
            if result.get("data").get("attributes"):
                count = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                file_info = result['data']['attributes']['meaningful_name']
                file_type = result['data']['attributes']['type_description']
                names= result['data']['attributes']['names']
                print ()
                s = PrettyTable()
                s.field_names = [                    
                    Colors.RED + "Malicious" + Colors.ENDC, 
                    Colors.YELLOW + "Suspicious" + Colors.ENDC, 
                    Colors.GREEN + "Clean" + Colors.ENDC, 
                    "Last Updated"
                ]
                s.add_row([
                    str(count.get("malicious")),
                    str(count.get("suspicious")),
                    str(count.get("undetected")),
                    str(last_update)
                ])

                print(s)
                time.sleep(1)
                print()

                u = PrettyTable()
                u.field_names = ["Engine Name", "Result"]
                for k in results:
                    if results[k].get("category") == "malicious":
                        u.add_row([results[k].get( "engine_name"), Colors.RED + results[k].get("result") + Colors.ENDC])

                print(u)
                print()
                time.sleep(2)
                print(Colors.GREY + 'File Name:', Colors.YELLOW + file_info + Colors.ENDC)
                print(Colors.GREY + 'File Type:', Colors.YELLOW + file_type + Colors.ENDC)
                print()
                name_list = (names)
                print(Colors.GREY + 'Related Names for the file:', Colors.ENDC)
                for name in name_list:  
                    print(Colors.YELLOW + name  + Colors.ENDC)
                print()
                time.sleep(2)
                print(Colors.GREY +'YARA Rules:'+ Colors.ENDC)
                count = 1
                if 'data' in result and 'attributes' in result['data']:
                    if 'crowdsourced_yara_results' in result['data']['attributes']:
                        crowdsourced_yara_results = result['data']['attributes']['crowdsourced_yara_results']
                        for item in crowdsourced_yara_results:
                            print(f"{Colors.GREY}{count}. author: {item['author']}{Colors.ENDC} \n\t {Colors.YELLOW} rule name: {item['rule_name']} \n\t  link: {item['source']}{Colors.ENDC}")
                            count += 1
                else:
                        print("No YARA results available for this resource.")
                
                time.sleep(2)
                print()
                print(Colors.GREY +'Sandbox Rules:'+ Colors.ENDC)
                if isinstance(result, dict):
                    if 'data' in result and 'attributes' in result['data']:
                        if 'sandbox_verdicts' in result['data']['attributes']:
                            sandbox_verdicts = result['data']['attributes']['sandbox_verdicts']

                            for k in sandbox_verdicts:
                                if sandbox_verdicts[k].get('category') == 'malicious':
                                    print(Colors.YELLOW + sandbox_verdicts[k]['sandbox_name'],':', '\nScore:', sandbox_verdicts[k].get('confidence'), '\nflags this file as:', sandbox_verdicts[k]['malware_classification'], Colors.ENDC)
                        else:
                            print("No sandbox verdicts available for this resource.")

                time.sleep(5)

                print()
                print('The last time the hash had been scanned was on: ' + Colors.GREY + str(last_update) + Colors.ENDC)
                yes_responses= {'y', 'yes'}
                retry = None
                retry = input('Do you want to rescan the hash: (yes/no): ').lower()
                if retry in yes_responses:
                    os.system('cls')
                    rescanurl = VT_URL + "files/" + hash + "/" + "analyse" 
                    res2 = requests.post(rescanurl, headers = headers)
                    result = res2.json()
                    u = PrettyTable()
                    u.field_names = ["Engine Name", "Result"]
                    for k in results:
                        if results[k].get("category") == "malicious":
                            u.add_row([results[k].get( "engine_name"), Colors.RED + results[k].get("result") + Colors.ENDC])
                    print(s)
                    print(u)
                else:
                    exit()
                
                     

        elif res.status_code == 400:
            print (Colors.RED + "connection error or wrong hash " + Colors.ENDC)
            print (Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
        else:
     
           print (Colors.BLUE + " Unknown Hash " + Colors.ENDC)

# This function takes multiple IPs and Domains and returns the results in a csv file.

def Ips_domians_check (ips_domians):
    target_file = ips_domians
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    csv_file = "Malicious_IPs_Domains.csv"
    header = ["IPs/Domains", "Hits"]
    # Creating the CSV file and writing the header into it

    with open(csv_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(header)

        # Reading the input file
        with open(target_file) as f:
            targets = f.read().splitlines()
        
        print(Colors.GREY + "Please wait while scanning" , target_file , Colors.ENDC)
        
        for target in targets:
            params = {"apikey": apikey, "resource": target}
            response = requests.get(url, params=params)
            if response.status_code == 204:  # if the used VT key is a public key, then its limited to 4 requites per minute
                print(
                    Colors.YELLOW + "You have reached the rate limits per minute; please wait 50 seconds." + Colors.ENDC)
                time.sleep(50)
            else:
                json_response = response.json()
                detected = json_response["positives"]
                writer.writerow([target, detected])
            
        print()
        print(Colors.GREEN + "The scan has been completed please check  " + os.path.abspath(csv_file) + " file " +  Colors.ENDC)

# scanning a single ip

def Ip_check(Ip):
    ipadd = Ip
    url = VT_URL + "ip_addresses/"+ ipadd 
    
    res = requests.get(url, headers = headers)
    if res.status_code == 200:
            result = res.json()
            # start parsing the json response
            last_update = datetime.datetime.fromtimestamp(result.get("data").get("attributes").get("last_modification_date"))
            if result.get("data").get("attributes"):
                count = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                info = result.get("data").get("attributes").get("tags") 
                contury = result.get("data").get("attributes").get("country")  
                print(Colors.GREY + "Start scanning the IP ... " + Colors.ENDC)
                print ()
                z = PrettyTable()
                z.field_names = ["Country", "Info", "Last Updated"]
                z.add_row([contury, ":".join(info), str(last_update)])
                print(z)
                print()
                y = PrettyTable()
                y.field_names = [Colors.RED + "malicious" + Colors.ENDC,
                                  Colors.YELLOW + "suspicious" + Colors.ENDC,
                                  Colors.GREEN + "clean" + Colors.ENDC
                                ]
                y.add_row([
                    str(count.get("malicious")),
                    str(count.get("suspicious")),
                    str(count.get("harmless"))                   
                ])
                print(y)
                print()
                x = PrettyTable()
                x.field_names = ["Engine Name", "Result"]
                for k in results:
                    if results[k].get("category") == "malicious":
                        x.add_row([results[k]["engine_name"], Colors.RED + results[k].get("result")  + Colors.ENDC])
                print(x)
                print()

def Domain_check(domain):
    domain = domain
    url = VT_URL + "domains/" + domain
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        print("Please chech your entered Domain")
        exit()
    result = res.json()
    if result.get("data").get("attributes"):
                # start parsing the json response
                count = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                categories = result['data']['attributes']['categories']

                print ()
                last_update = datetime.datetime.fromtimestamp(result.get("data").get("attributes").get("last_modification_date"))
                print(Colors.YELLOW + "[!] Start scanning " + domain + Colors.ENDC)
                print()
                
                s = ''
                for key, value in categories.items():
                    s += f'{key}: {value}\n'
                c = PrettyTable()
                c.field_names = ["categories"]
                colored_s = '{}{}{}'.format(Colors.YELLOW, s, Colors.ENDC)
                c.add_row([colored_s])
                print(c)
                
                v = PrettyTable()
                v.field_names = [
                    Colors.RED + "Malicious" + Colors.ENDC, 
                    Colors.YELLOW + "Suspicious" + Colors.ENDC, 
                    Colors.GREEN + "Clean" + Colors.ENDC, 
                    "Last Updated"
                ]
                v.add_row([str(count.get("malicious")), str(count.get("suspicious")), str(count.get("harmless")),str(last_update) ])
                print(v)
                print()
                w = PrettyTable()
                w.field_names = ["Engine Name", "Result"]
            
              
          
                for k in results:
                    if results[k].get("category") == "malicious":
                        w.add_row([
                            results[k]["engine_name"],
                            Colors.RED + results[k]["result"] + Colors.ENDC
                        ])
             
                print(w)
                print()                

                for i in results:
                    if results[i].get("category") == "suspicious":
                        
                        print ("result : " + Colors.RED + results[i].get("result") + Colors.ENDC)
                        print ()

# scanning the file based on the hash
def File_scann(file):
    file = file 
    chunk = 65536 
    file_hash = hashlib.md5() 
    with open(file, 'rb') as f: 
        read_as_bytes = f.read(chunk) 
        while len(read_as_bytes) > 0: 
            file_hash.update(read_as_bytes) 
            read_as_bytes = f.read(chunk) 
    md5hash= file_hash.hexdigest()
    
    url_info = VT_URL + "files/" + md5hash 
    res = requests.get(url_info ,headers = headers)
    if res.status_code == 200:
        result = res.json()
        last_update = datetime.datetime.fromtimestamp(result.get("data").get("attributes").get("last_modification_date"))
        if result.get("data").get("attributes"):
                count = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                print ()
                s = PrettyTable()
                s.field_names = [                    
                    Colors.RED + "Malicious" + Colors.ENDC, 
                    Colors.YELLOW + "Suspicious" + Colors.ENDC, 
                    Colors.GREEN + "Clean" + Colors.ENDC, 
                    "Last Updated"
                ]
                s.add_row([
                    str(count.get("malicious")),
                    str(count.get("suspicious")),
                    str(count.get("undetected")),
                    str(last_update)
                ])

                print(s)
                print()

                u = PrettyTable()
                u.field_names = ["Engine Name", "Result"]
                for k in results:
                    if results[k].get("category") == "malicious":
                        u.add_row([results[k].get( "engine_name"), Colors.RED + results[k].get("result") + Colors.ENDC])

                print(u)
                print()
                
    elif res.status_code == 400:
            print (Colors.RED + " connection error or wrong hash " + Colors.ENDC)
            print (Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
    else:
     
           print (Colors.BLUE + " Unknown Hash " + Colors.ENDC)
        
        
if __name__ == "__main__":
    logo = '''
____    ____ .___________.     ______  __    __   _______   ______  __  ___  _______ .______      
\   \  /   / |           |    /      ||  |  |  | |   ____| /      ||  |/  / |   ____||   _  \     
 \   \/   /  `---|  |----`   |  ,----'|  |__|  | |  |__   |  ,----'|  '  /  |  |__   |  |_)  |    
  \      /       |  |        |  |     |   __   | |   __|  |  |     |    <   |   __|  |      /     
   \    /        |  |        |  `----.|  |  |  | |  |____ |  `----.|  .  \  |  |____ |  |\  \----.
    \__/         |__|         \______||__|  |__| |_______| \______||__|\__\ |_______|| _| `._____|
                                                                                                  
 '''

    print(logo)
    print(Colors.GREEN + "\t\t" + AUTHOR + "  Version: " + VERSION + Colors.ENDC)
    print("\n")
    parser = argparse.ArgumentParser(description=" A python script to chech hashes, ips, domains and download executables by a hash", add_help=False)
    parser.add_argument("-a" , help='executable hash that you want to download ' , metavar='')
    parser.add_argument('-l', help='scan multiple ips, domains, or both.', metavar='')
    parser.add_argument('-s', type= str, help='scan a single ip, domain, or hash', metavar='')
    parser.add_argument('-f' , help = 'executable path for scanning ', metavar='')
    args = parser.parse_args()

    if len(sys.argv) <= 1:
         parser.print_help()
         exit(1)

    if len(apikey) == 0:
     print(Colors.RED + "Please add your api key to .env file" + Colors.ENDC )
     exit()
    
    if args.a:
        DownloadFile(args.a)

    elif args.l:
        Ips_domians_check(args.l)
    
    elif args.f:
        File_scann(args.f)
        
        
    elif args.s:

        if re.search(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b", args.s):
            Ip_check(args.s)

        elif re.search(r"[a-fA-F0-9]{32}", args.s) or re.search(r"[a-fA-F0-9]{40}", args.s)  or re.search(r"[a-fA-F0-9]{64}", args.s) or re.search(r"[a-fA-F0-9]{128}", args.s):
            Check_hash(args.s)

        elif re.search(r"\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b", args.s):
            Domain_check(args.s)
        
        else:
             print(Colors.RED + "Please check your entery" + Colors.ENDC)

    
