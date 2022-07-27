import requests
import docker
import re,os,json,tempfile
from git import Repo

keys = {}
for line in open('keys.txt','r'):
    key,value = line.strip().split(':')
    keys[key] = value

def get_url_of_package(package, platform):
    r = requests.get(f"https://libraries.io/api/{platform}/{package}?api_key={keys['libraries']}")
    return r.json()['repository_url']    

def cve_detection(url,client):
    client.containers.run('aquasec/trivy',f'repo -f json -o results.json {url}',working_dir=os.getcwd())

def scan_urls(repo):
    tempdir = tempfile.TemporaryDirectory()
    Repo.clone_from(repo, tempdir.name)
    urls = []
    for root, dirs, files in os.walk(tempdir.name):
        for file in files:
            try:
                urls += re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',open(os.path.join(root,file),'r').read())
            except (FileNotFoundError,UnicodeDecodeError):
                pass
    urls = list(set(urls))
    tempdir.cleanup()
    body = {
    "client": {
      "clientId":      "nuttynotty",
      "clientVersion": "1.0.0"
    },
    "threatInfo": {
      "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING"],
      "platformTypes":    ["WINDOWS"],
      "threatEntryTypes": ["URL"],
      "threatEntries": []
      }
    }
    print(urls)
    limit = 0
    while limit < len(urls):
        body['threatInfo']['threatEntries'] = [ {"url" : url} for url in urls[limit:limit+500]]
        r = requests.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={keys["google"]}',json=body,headers={'Content-Type': 'application/json'})
        limit += 500
        print(r.json())

def main():
    client = docker.from_env()
#    cve_detection('https://github.com/d4rkc0de-club/BugSmash',client)
    print(get_url_of_package('dicer','NPM'))
    scan_urls("https://github.com/BuonOmo/unsafe")

if __name__ == '__main__':
    main()
