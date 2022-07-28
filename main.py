import requests
from bs4 import BeautifulSoup
import docker
import re,os,json,tempfile,datetime, sys
from git import Repo
from github import Github
from flask import Flask, render_template, request

app = Flask(__name__)
keys = {}
for line in open('keys.txt','r'):
    key,value = line.strip().split(':')
    keys[key] = value

g = Github(keys['github'])
client = docker.from_env()

def get_url_of_package(package, platform):
    if platform == "NPM":
        url = f"https://www.npmjs.com/package/{package}"
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        return soup.find_all('a', {'aria-labelledby':'repository'})[0].get('href')
    elif platform == 'Pypi':
        repos = g.search_repositories(f'{package} language:python')
        return repos[0].html_url

def cve_detection(url):
    raw = client.containers.run('aquasec/trivy',f'repo -f json {url}').decode('utf-8')
    for i,line in enumerate(raw.split('\n')):
        if 'Total' in line:
            return '\n'.join(raw.split('\n')[i+1:])

def scan_files(repo):
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
    return num_vuln_urls

def metadata_analysis(repo):
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
        authors_score += author.followers
    score = authors_score * 0.3 + stars - num_issues*10 - (datetime.datetime.now() - last_committed).days / 10 - topic_sensitive * 100
    return score, topic_sensitive

def main(url, logfile=None):
    if logfile is None:
        logfile = open('logs.log','w')
    logfile.write("Running Trivy...")
    cves = json.loads(cve_detection(url))
    severity = {'LOW':0,'MEDIUM':0,'HIGH':0,'CRITICAL':0}
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
    logfile.write(f"Severity: {severity}")
    logfile.write("Scanning files and github")
    num_trash_urls = scan_files(url)
    repo_score, topics = metadata_analysis(url)
    return {'severity':severity,'num_trash_urls':num_trash_urls,'repo_score':repo_score,'topics':topics}
    
@app.route('/')
def index():
    return render_template('form.html')

@app.route('/result',methods=['GET'])
def result():
    url = request.args.get('url')
    result = main(url)
    message = "This repo cannot be said to be malicious or malicious, but the low amount of eyeballs on it make it not trustworthy enough to use on a large scale without verification."
    if result['topics'] or result['severity'] > 0:
        message = "This repo can be malicious"
    result['repo_score'] -= result['severity']['LOW'] * 3 + result['severity']['MEDIUM'] * 5 + result['severity']['HIGH'] * 8 + result['severity']['CRITICAL'] * 12
    if result['repo_score'] < 30:
        message = 'This repo can be vulnerable'
    elif result['repo_score'] > 100:
        message= "This repo is very secure"
    return render_template('result.html',message=message, low = result['severity']['LOW'],
                            medium = result['severity']['MEDIUM'], high = result['severity']['HIGH'], critical = result['severity']['CRITICAL'])