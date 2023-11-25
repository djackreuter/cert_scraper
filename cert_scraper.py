import sys
import os
import requests
import argparse
import binascii
import shutil
from datetime import datetime, timedelta
from termcolor import cprint
from asn1crypto import pkcs12

def make_request(api_key, prev_days):
    resp = requests.get("https://buckets.grayhatwarfare.com/api/v2/files?extensions=pfx", headers={"Authorization": f"Bearer {api_key}"})

    if resp.status_code == 401:
        cprint(f"[!] Check your API key and try again!", "red")
        sys.exit(1)

    data = resp.json()

    time_now = datetime.now()
    time_start = timedelta(days=int(prev_days))

    file_urls = list()
    for file in data['files']:
        last_modified = datetime.fromtimestamp(file['lastModified'])
        if last_modified >= time_now - time_start:
            file_urls.append(file['url'])

    return file_urls


def get_file(file):
    file_data = requests.get(file)
    filename = file.rsplit('/', 1)[-1]
    with open(f"{dir_name}/{filename}", 'wb') as f:
        f.write(file_data.content)
    return filename


def check_sequence(filename):
    seq_found = False
    with open(f"{dir_name}/{filename}", 'rb') as file:
        file.seek(4)
        filebytes = file.read(4)
        if filebytes.hex() == '02010330':
            cprint(f"Cert found! {filename}", "green")
            seq_found = True

    if not seq_found:
        os.remove(f"{dir_name}/{filename}")

    return seq_found


def generate_hash_file(certs, dir_name):
    for filename in certs:
        # pfx2john stolen from Will Bond and Dhiru Kholia
        # https://gist.github.com/tijme/86edd06c636ad06c306111fcec4125ba
        with open(f"{dir_name}/{filename}", "rb") as file:
            data = file.read()
            try:
                pfx = pkcs12.Pfx.load(data)
            except:
                print(f"{filename} is incorrect 1.")
                shutil.move(filename, filename.replace('certs', 'certs_deleted'))
                return

            try:
                auth_safe = pfx['auth_safe']
            except:
                print(f"{filename} is incorrect 2.")
                shutil.move(filename, filename.replace('certs', 'certs_deleted'))
                return

            if auth_safe['content_type'].native != 'data':
                print(f"{filename} is incorrect 3.")
                shutil.move(filename, filename.replace('certs', 'certs_deleted'))
                return

            mac_data = pfx['mac_data']
            if mac_data:
                mac_algo = mac_data['mac']['digest_algorithm']['algorithm'].native

                try:
                    key_length = {
                        'sha1': 20,
                        'sha224': 28,
                        'sha256': 32,
                        'sha384': 48,
                        'sha512': 64,
                        'sha512_224': 28,
                        'sha512_256': 32,
                    }[mac_algo]
                except:
                    print(str(mac_data['mac']['digest_algorithm']))
                    shutil.move(filename, filename.replace('certs', 'certs_deleted'))
                    sys.exit()

                salt = mac_data['mac_salt'].native
                iterations = mac_data['iterations'].native
                mac_algo_numeric = -1
                if mac_algo == "sha1":
                    mac_algo_numeric = 1
                elif mac_algo == "sha224":
                    mac_algo_numeric = 224
                elif mac_algo == "sha256":
                    mac_algo_numeric = 256
                elif mac_algo == "sha384":
                    mac_algo_numeric = 384
                elif mac_algo == "sha512":
                    mac_algo_numeric = 512
                else:
                    print(f"mac_algo {mac_algo} is not supported yet!")
                    return
                stored_hmac = mac_data['mac']['digest'].native
                data = auth_safe['content'].contents
                size = len(salt)
                sys.stdout.write("%s:$pfxng$%s$%s$%s$%s$%s$%s$%s:::::%s\n" %
                                (os.path.basename(filename), mac_algo_numeric,
                                key_length, iterations, size, binascii.hexlify(salt).decode(),
                                binascii.hexlify(data).decode(),
                                binascii.hexlify(stored_hmac).decode(), filename))

                hash = f"{os.path.basename(filename)}:$pfxng${mac_algo_numeric}${key_length}${iterations}${size}${binascii.hexlify(salt).decode()}${binascii.hexlify(data).decode()}${binascii.hexlify(stored_hmac).decode()}:::::{filename}\n"
                with open(f"{dir_name}/hashes", "a", encoding="utf8") as f:
                    f.write(hash)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="cert_scraper", description="Scrape GrayHat Warefare for leaked code signing certificates. Outputs certificate hashes to crack with JtR")
    parser.add_argument("--api-key", help="GrayHat Warefare API key", required=True)
    parser.add_argument("-d", "--days", help="Find certs uploaded within the last X days", required=True)
    args = parser.parse_args()

    print("[+] Searching for certificates")
    files = make_request(args.api_key, args.days)

    if len(files) == 0:
        cprint("[!] No certificates found in that timeframe!", "red")
        sys.exit(1)

    time_now = datetime.now()
    timestamp = time_now.strftime("%Y%m%d%H%M%S")
    dir_name = f"certs_{timestamp}"
    os.mkdir(dir_name)

    total = 0
    certs = list()
    for file in files:
        filename = get_file(file)
        if check_sequence(filename):
            certs.append(filename)
            total += 1


    if total == 0:
        cprint("[!] No code signing certificates found!", "red")
        sys.exit(1)

    generate_hash_file(certs, dir_name)

    cprint(f"[\N{CHECK MARK}] Found {total} certificate(s)!", "green")
    print(f"[+] Certificate(s) saved in: {dir_name}")
    print(f"[+] Hash file saved to: {dir_name}/hashes")
