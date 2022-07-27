import requests
import docker
from bs4 import BeautifulSoup
import re,os


def get_url_of_npm_package(url):
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    return soup.find('a', {'aria-labelledby':'repository'})['href']

def get_url_of_py_package(url):
    pack_name = re.match('https://pypi.org/project/(.*)', url).group(1)
    libraries_url = f'https://libraries.io/pypi/{pack_name}'
    r = requests.get(libraries_url)
    soup = BeautifulSoup(r.text, 'html.parser')
    return soup.find('p', {'class':'project-links'}).findAll('a')[1]['href']

def cve_detection(url,client):
    client.containers.run('aquasec/trivy',f'repo -f json -o results.json {url}',working_dir=os.getcwd())

def main():
    client = docker.from_env()
    cve_detection('https://github.com/d4rkc0de-club/BugSmash',client)

if __name__ == '__main__':
    main()
