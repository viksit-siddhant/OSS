# Notty OSS
This is an app that helps to determine the trustworthiness of a repo.

## How to set this up for yourself
1. Clone the repository and cd into it
2. Run ``` pip install -r requirements.txt ```
3. Make a file called `keys.txt` of the format
````
github:{GITHUB PAT}
libraries:{LIBRARIES.IO API KEY}
google:{GOOGLE LOOKUP API V4 KEY}
````
3. Make sure docker is installed on your system
4. Run ```python main.py```
