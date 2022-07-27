from git import Repo
import json, requests, os, logging, tempfile
from requests.structures import CaseInsensitiveDict
import re

logging.basicConfig(level=logging.INFO, filename="logs.log")
tempdir = tempfile.TemporaryDirectory()
Repo.clone_from("https://github.com/d4rkc0de-club/BugSmash", tempdir.name)
try:
    with open(f"{tempdir.name}/package.json", "r") as f:
        packages = json.load(f)
        for package,version in packages["dependencies"].items():
            print(package)
except FileNotFoundError:
    logging.info("No package.json found")

imports = []
for root, dirs, files in os.walk(tempdir.name):
    for file in files:
        if file.endswith(".py"):
            for line in open(f"{root}/{file}", "r"):
                if "import" in line:
                    if "from" in line:
                        imports.append(line.split("from")[1].split("import")[0].strip())
                    else:
                        lists, final = re.findall("import (.*),*(.*)",line)[0]

                        for lib in lists.replace(' ','').split(","):
                            imports.append(lib)
                        if final:
                            imports.append(final.strip())

imports = list(set(imports))
imports = [i.split('.')[0] for i in imports]
print(imports)
tempdir.cleanup()