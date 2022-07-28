import requests
import docker
import re,os,json,tempfile,datetime, sys
from git import Repo
from github import Github

keys = {}
for line in open('keys.txt','r'):
    key,value = line.strip().split(':')
    keys[key] = value

def get_url_of_package(package, platform):
    url = f"https://libraries.io/api/{platform}/{package}"
    cache = open('cache.txt','r')
    for entry in cache:
        if entry.split(':')[0] == url:
            return entry.split(':')[1]
    cache.close()
    cache = open('cache.txt','a')
    r = requests.get(f"{url}?api_key={keys['libraries']}")
    destination = r.json()['repository_url']    
    cache.write(f"{url}:{destination}\n")
    cache.close()
    return destination

def cve_detection(url,client):
    raw = client.containers.run('aquasec/trivy',f'repo -f json {url}').decode('utf-8')
    for i,line in enumerate(raw.split('\n')):
        if 'Total' in line:
            return '\n'.join(raw.split('\n')[i+1:])

def scan_files(repo):
    tempdir = tempfile.TemporaryDirectory()
    Repo.clone_from(repo, tempdir.name)
    packages = []
    try:
        with open(os.path.join(tempdir.name, 'package.json'), 'r') as f:
            for package in json.load(f)['dependencies']:
                packages.append((package,'NPM'))
    except FileNotFoundError:
        pass
    urls = []
    builtins = set([module.replace('_',"") for module in sys.builtin_module_names])
    for root, dirs, files in os.walk(tempdir.name):
        for file in files:
            try:
                urls += re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',open(os.path.join(root,file),'r').read())
                if file.endswith('.py'):
                    for line in open(os.path.join(root,file), "r"):
                        if "import" in line:
                            if "from" in line:
                               packages.append((line.split("from")[1].split("import")[0].strip(),'Pypi'))
                            else:
                                lists, final = re.findall("import (.*),*(.*)",line)[0]

                                for lib in lists.replace(' ','').split(","):
                                    packages.append((lib.strip(),'Pypi'))
                                if final:
                                    packages.append((final.strip(),'Pypi'))
            except (FileNotFoundError,UnicodeDecodeError):
                pass
    dep_score = 9999999999999
    packages = list(set(packages))
    for package, platform in packages:
        if package not in builtins:
            try:
                url = get_url_of_package(package, platform)
                repo_analysis = metadata_analysis(url)
                dep_score = min(dep_score,repo_analysis['authorScore'])
            except KeyError:
                dep_score -= 50
    urls = list(set(urls))
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
    limit = 0
    num_vuln_urls = 0
    while limit < len(urls):
        body['threatInfo']['threatEntries'] = [ {"url" : url} for url in urls[limit:limit+500]]
        r = requests.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={keys["google"]}',json=body,headers={'Content-Type': 'application/json'})
        limit += 500
        if r.json():
            num_vuln_urls += len(r.json()['matches'])

    tempdir.cleanup()
    return num_vuln_urls, dep_score

def metadata_analysis(repo):
    g = Github(keys['github'])
    repo = g.get_repo('/'.join(repo.split('/')[-2:]))
    stars = repo.stargazers_count
    num_issues = repo.open_issues_count
    blacklist = ['hacking','trojan','backdoor','malware']
    whitelist = ['protection','malware-analysis','forensics']
    topic_sensitive = False
    for topic in repo.get_topics():
        if topic in blacklist and topic not in whitelist:
            topic_sensitive = True
    last_committed = repo.get_commits()[0].commit.author.date
    authornames = []
    for commit in repo.get_commits():
        authornames.append(commit.commit.author.name)
    authornames = list(set(authornames))
    authors = []
    for author in authornames:
        try:
            authors.append(g.get_user(author))
        except Exception:
            pass
    authors_score = 0
    for author in authors:
        for repo in author.get_repos():
            authors_score += repo.stargazers_count
            for topic in repo.get_topics():
                if topic in blacklist and topic not in whitelist:
                    authors_score -= repo.stargazers_count
                    authors_score -= author.followers
                    break
        authors_score += author.followers
    score = authors_score * 0.3 + stars - num_issues*10 - (datetime.datetime.now() - last_committed).days / 10 - topic_sensitive * 100
    return score

def main(url, logfile=None):
    if logfile is None:
        logfile = open('logs.log','w')
    client = docker.from_env()
    cves = json.loads(cve_detection(url,client))
    severity = {}
    try:
        for class_vulns in cves['Results']:
            for vuln in class_vulns['Vulnerabilities']:
                logfile.write(vuln['Title'])
                if 'FixedVersion' in logfile:
                    logfile.write(f'\nFixedVersion: {vuln["FixedVersion"]}')
                logfile.write(f'\n{vuln["Severity"]}')
                if vuln['Severity'] not in severity:
                    severity[vuln['Severity']] = 1
                else:
                    severity[vuln['Severity']] += 1
    except KeyError:
        pass
    num_trash_urls, dep_score = scan_files(url)
    repo_score = metadata_analysis(url)
    print(repo_score,dep_score)
    print(num_trash_urls)
    print(severity)


if __name__ == '__main__':
    main('https://github.com/encryptedcation/NoDoubt')
