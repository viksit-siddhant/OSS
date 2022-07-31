import requests
from bs4 import BeautifulSoup
import docker
import re, os, json, tempfile, datetime, sys
from git import Repo
from github import Github
from flask import Flask, render_template, request

app = Flask(__name__)
keys = {}

for line in open("keys.txt", "r"):
    k, v = line.strip().split(":")
    keys[k] = v

g = Github(keys["github"])
client = docker.from_env()


def get_package_of_url(url, platform):
    if platform == "NPM":
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        return soup.find_all("a", {"aria-labelledby": "repository"})[0].get("href")
    elif platform == "Pypi":
        if url.endswith("/"):
            url = url[:-1]
        repo_name = re.findall("pypi.org/project/(.+)", url)[0]
        if repo_name == "":
            raise ValueError("Not valid pypi link")
    r = requests.get(
        f"https://libraries.io/api/Pypi/{repo_name}?api_key={keys['libraries']}"
    )
    return r.json()["repository_url"]


def cve_detection(url):
    raw = client.containers.run("aquasec/trivy", f"repo -f json {url}").decode("utf-8")
    for i, line in enumerate(raw.split("\n")):
        if "Total" in line:
            return "\n".join(raw.split("\n")[i + 1 :])


def scan_files(repo):
    tempdir = tempfile.TemporaryDirectory()
    Repo.clone_from(repo, tempdir.name)
    urls = []
    for root, dirs, files in os.walk(tempdir.name):
        for file in files:
            try:
                urls += re.findall(
                    "https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
                    open(os.path.join(root, file), "r").read(),
                )
            except (FileNotFoundError, UnicodeDecodeError):
                pass
    urls = list(set(urls))
    body = {
        "client": {"clientId": "nuttynotty", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["WINDOWS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [],
        },
    }
    limit = 0
    num_vuln_urls = 0
    while limit < len(urls):
        body["threatInfo"]["threatEntries"] = [
            {"url": url} for url in urls[limit : limit + 500]
        ]
        r = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={keys["google"]}',
            json=body,
            headers={"Content-Type": "application/json"},
        )
        limit += 500
        if "matches" in r.json():
            num_vuln_urls += len(r.json()["matches"])

    tempdir.cleanup()
    return num_vuln_urls


def metadata_analysis(repo):
    repo = g.get_repo("/".join(repo.split("/")[-2:]))
    stars = repo.stargazers_count
    num_issues = repo.open_issues_count
    blacklist = ["hacking", "trojan", "backdoor", "malware"]
    whitelist = ["protection", "malware-analysis", "forensics"]
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
    score = (
        authors_score * 0.3
        + stars
        - num_issues * 10
        - (datetime.datetime.now() - last_committed).days / 10
        - topic_sensitive * 100
    )
    return score, topic_sensitive, stars


def main(url):
    cves = json.loads(cve_detection(url))
    severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    try:
        for class_vulns in cves["Results"]:
            for vuln in class_vulns["Vulnerabilities"]:
                if vuln["Severity"] not in severity:
                    severity[vuln["Severity"]] = 1
                else:
                    severity[vuln["Severity"]] += 1
    except KeyError:
        pass
    num_trash_urls = scan_files(url)
    repo_score, topics, stars = metadata_analysis(url)
    return {
        "severity": severity,
        "stars": stars,
        "num_trash_urls": num_trash_urls,
        "repo_score": repo_score,
        "topics": topics,
    }


@app.route("/")
def index():
    return render_template("form.html")


@app.route("/result", methods=["GET"])
def result():
    url = request.args.get("URL")
    try:
        if "pypi.org" in url:
            url = get_package_of_url(url, "Pypi")
        elif "npmjs.com" in url:
            url = get_package_of_url(url, "NPM")
        result = main(url)
    except Exception:
        return render_template("error.html")
    message = "This repo cannot be said to be malicious or malicious, but the low amount of eyeballs on it make it not trustworthy enough to use on a large scale without verification."
    result["repo_score"] -= (
        result["severity"]["LOW"] * 3
        + result["severity"]["MEDIUM"] * 5
        + result["severity"]["HIGH"] * 10
        + result["severity"]["CRITICAL"] * 12
    )
    if (
        result["topics"]
        or result["num_trash_urls"] > 0
        or result["severity"]["CRITICAL"] > 0
    ):
        message = "This repo can be malicious"
    elif result["repo_score"] > 100:
        message = "This repo is very secure"
    result["repo_score"] = min(result["repo_score"], 100)
    result["repo_score"] = max(result["repo_score"], 0)
    return render_template(
        "result.html",
        message=message,
        stars=result["stars"],
        total_cves=result["severity"]["HIGH"],
        critical=result["severity"]["CRITICAL"],
        score=result["repo_score"] / 10,
        num_url=result["num_trash_urls"],
    )


app.run(host="0.0.0.0", port=80)
