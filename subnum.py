#!/usr/bin/env python3
#thenurhabib

__Name__ = "subNum"
__Author__ = "Md. Nur habib"
__Discription__ = "Crawl all URLs and check for subdomain takeover vulnerability."
__Version__ = "1.0"

# Import Modules
import os
import sys
import threading
import subprocess
import argparse
import dns.resolver
import aiohttp
import asyncio
from aiohttp import *
import time

if sys.platform.startswith('win'):
    os.system('cls')


class style:
    reset='\033[0m'
    bold='\033[01m'
    black='\033[30m'
    red='\033[31m'
    green='\033[32m'
    orange='\033[33m'
    blue='\033[34m'
    purple='\033[35m'
    cyan='\033[36m'
    lightgrey='\033[37m'
    darkgrey='\033[90m'
    lightred='\033[91m'
    lightgreen='\033[92m'
    yellow='\033[93m'
    lightblue='\033[94m'
    pink='\033[95m'
    lightcyan='\033[96m'


def bannerFunction():
    print(f"""{style.bold}{style.yellow}

           | |   | \ | | {__Version__}              
  ___ _   _| |__ |  \| |_   _ _ __ ___  
 / __| | | | '_ \| . ` | | | | '_ ` _ \ 
 \__ \ |_| | |_) | |\  | |_| | | | | | |
 |___/\__,_|_.__/|_| \_|\__,_|_| |_| |_|{style.reset}
                           {style.red} @thenurhabib {style.reset}{style.bold}{style.yellow}
========================================{style.reset}
          """)


bannerFunction()


uniqueDomain = []
valiableURLs = []
inputURL = []


class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/-\\':
                yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay):
            self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b')
            sys.stdout.flush()

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def __exit__(self, exception, value, tb):
        self.busy = False
        time.sleep(self.delay)
        if exception is not None:
            return False


def main():

    parser = argparse.ArgumentParser(
        description='Crawl all subdomains and check for subdomain takeover vulnerability.')
    parser.add_argument(
        '-d', '--domain', help='Domain name of the taget [ex : example.com]')
    parser.add_argument(
        '-f', '--file', help='Provide location of subdomain file.')
    parser.add_argument(
        '-o', '--output', help='Output unique subdomains of sublist3r and subfinder.', default='uniqueURL.txt')
    parser.add_argument(
        '-p', '--protocol', help='Set protocol for requests. Default is "http" [ex: --protocol https]', default='http')
    args = parser.parse_args()

    def getSubdomain(subData):

        try:
            stdout_string = subprocess.check_output(
                ['subfinder', '-silent', '-version'], stderr=subprocess.STDOUT)

            try:
                stdout_string = subprocess.check_output(
                    ['sublist3r'], stderr=subprocess.STDOUT)
                print(
                    f'{style.blue} {style.bold}[-] Default http [use -p https]\n')
                print(f'{style.blue}[-] Testing All Subdomains...\n')
                time.sleep(2)

               
                print(
                    f'{style.orange}Enumerating subdomains : {style.cyan} {args.domain}')
                print("========================")
                
                with Spinner():
                    os.popen('sublist3r -d '+subData +
                             ' -o sublist3r_list.txt').read()
                    os.popen('subfinder -t 15 -d  '+subData +
                             ' -silent > subfinder_list.txt').read()

            except subprocess.CalledProcessError as cpe:
                print(
                    f'{style.red}[!] Sublist3r not found!!!\n{style.green}[-] Install it or use -f with subdomain.txt file.')
                sys.exit()

            except OSError as e:
                print(
                    f'{style.red}[!] Sublist3r not found!!!\n{style.green}[-] Install it or use -f with subdomain.txt file.')
                sys.exit()

        except subprocess.CalledProcessError as cpe:
            print(
                f'{style.red}[!] Subfinder not found!!!\n{style.green}[-] Install it or use -f with subdomain.txt file.')
            sys.exit()

        except OSError as e:
            print(
                f'{style.red}[!] Subfinder not found!!!\n{style.green}[-] Install it or use -f with subdomain.txt file.')
            sys.exit()

        if os.path.isfile('sublist3r_list.txt'):
            pass
        else:
            fpa = open("sublist3r_list.txt", "w")
            fpa.close()

        lines1 = open("sublist3r_list.txt", "r").readlines()
        lines2 = open('subfinder_list.txt', 'r').readlines()
        data1 = []
        data2 = []

        for line in lines1:
            data1.append(line.strip())

        for line in lines2:
            data2.append(line.strip())

        if os.path.isfile('sublist3r_list.txt'):
            os.remove('sublist3r_list.txt')

        if os.path.isfile('subfinder_list.txt'):
            os.remove('subfinder_list.txt')

        for x in data1:
            uniqueDomain.append(args.protocol+'://'+x)

        for line_diff in data2:
            if line_diff not in data1:
                uniqueDomain.append(args.protocol+'://'+line_diff)

        print(f'{style.green}[-] Total Unique Subdomain Found: ' +
              " "+str(sum(1 for line in uniqueDomain)))

        # To store unique subdomain in Text file
        with open(args.output, 'w') as fp:
            for x in uniqueDomain:
                if 'http://' or 'https://' in x:
                    r = x.replace("https://", "")
                    r = r.replace("http://", "")
                    fp.write(r+"\n")
            fp.close()
        with Spinner():
            asyncio.run(getCode())

        if len(valiableURLs) == 0:
            print(f'{style.green}[*] Task Completed :)')
            print(f'{style.orange}!] Target is not vulnerable!!!')
            sys.exit()

        cnameExtract(valiableURLs)

    # Get url which has 404 respose code

    def getResponseCode(inputFile):

        try:
            data = open(inputFile, "r")
            print(' Reading file '+'{style.green}'+inputFile)
            print(f'{style.blue}[-] Gathering Information...')

            time.sleep(2)
            print(f'{style.green}[-] Total Unique Subdomain Found: ' +
                  " "+str(sum(1 for line in open(inputFile, 'r'))))
            time.sleep(1)
            print(f'{style.blue}[-] Default http [use -p https] ')
            time.sleep(1)
            print(f'{style.blue}[-] Checking response code...')

        except NameError:
            print(f"\n!] {inputFile }File not found...!!!\n{style.blue}[-] Check filename and path.")
            sys.exit()

        except IOError:
            print(f"\n!] {inputFile} File not found...!!!\n{style.blue}[-]Check filename and path.")
            sys.exit()

        subdomain = data.readlines()

        for line in subdomain:
            if 'http://' or 'https://' in line:
                inputURL.append(line.strip())

            else:
                inputURL.append(args.protocol+"://"+line.strip())

        with Spinner():
            asyncio.run(urlCode())

        if len(valiableURLs) == 0:
            print(f'{style.green}[*] Task Completed :)')
            print('!] Target is not vulnerable!!!')
            sys.exit()

        cnameExtract(valiableURLs)

    # Extract CNAME records

    def cnameExtract(invalidURLs):

        print(f'{style.blue}[-] Checking CNAME records...\n')

        for x in invalidURLs:
            if 'http://' or 'https://' in x:
                data = x.replace('https://', '')
                data = x.replace('http://', '')

            else:
                pass

            try:

                resolve = dns.resolver.query(data.strip(), 'CNAME')

                for rdata in resolve:
                    cdata = (rdata.to_text()).strip()
                    targetDomain = data.strip()

                    if targetDomain[-8:] not in cdata:
                        print(f'\n Vulnerability Possible on: '+'{style.blue}'+str(
                            data)+"\n\t"+'{style.green}CNAME: '+'{style.green}'+str(rdata.to_text()))

                    else:
                        print(f'\n{style.blue}[-] '+str(data) +
                              '\n'+'\tNot Vulnerable')

            except:
                print(f'\n{style.blue}[-] '+str(data) +
                      '\n'+'\tNot Vulnerable.')

        print(f'{style.green}[*] Task Completed :)')
        sys.exit()

    if args.file:
        if args.domain:
            print('!] Use only -f option with subdomain file.')
            sys.exit()

        else:
            pass

        getResponseCode(args.file)

    else:
        pass

    if args.domain:
        if 'http://' in args.domain or 'www.' in args.domain or 'https://' in args.domain:
            args.domain = args.domain.replace('https://', '')
            args.domain = args.domain.replace('http://', '')
            args.domain = args.domain.replace('www.', '')
            getSubdomain(args.domain)

        else:
            getSubdomain(args.domain)

    else:
        print(
            f'{style.blue}{style.bold} for usage run :python subnum.py -h{style.reset}{style.bold}')


async def getCode():
    async with aiohttp.ClientSession() as session:
        await gen_tasks(session, 'random.txt')


async def urlCode():
    async with aiohttp.ClientSession() as session:
        await gen_input_tasks(session, 'random.txt')


async def fetch_url(session, url):
    count = 0
    try:
        async with session.get(url) as response:
            reason = response.reason
            status = response.status

            if status == 404:
                valiableURLs.append(url)
                pass
            else:
                pass

    except ClientConnectionError:
        return (url, 500)
    except ClientOSError:
        return (url, 500)
    except ServerDisconnectedError:
        return (url, 500)
    except asyncio.TimeoutError:
        return (url, 500)
    except UnicodeDecodeError:
        return (url, 500)
    except TooManyRedirects:
        return (url, 500)
    except ServerTimeoutError:
        return (url, 500)
    except ServerConnectionError:
        return (url, 500)
    except RuntimeError:
        pass
    except OSError:
        pass
    except Exception as err:
        pass


async def gen_input_tasks(session, url_list):

    tasks = []
    print(f'{style.blue}[-] Getting URL\'s of 404 status code...')

    for url in inputURL:
        task = asyncio.ensure_future(fetch_url(session, url))
        tasks.append(task)

    result = await asyncio.gather(*tasks)
    print(f'{style.green}[-] URL Checked: '+str(len(inputURL)))
    time.sleep(1)
    return result


async def gen_tasks(session, url_list):

    tasks = []
    print(f'{style.blue}[-] Getting URL\'s of 404 status code...')

    for url in uniqueDomain:
        task = asyncio.ensure_future(fetch_url(session, url))
        tasks.append(task)

    result = await asyncio.gather(*tasks)
    print(f'{style.green}[-] URL Checked: '+str(len(uniqueDomain)))
    time.sleep(1)
    return result

if __name__ == "__main__":
    main()
