# HARryParser

Installation:
1. Clone this repo
2. Install requirements from requirements.txt
3. Run harryparser.py with appropriate arguments

Examples:
<code>
  python3 harryparser.py <myfile.har> -p <mydomain.com>
  </code>
In this example, you are running the tool against the .har file you generated for a domain mydomain.com. 

The tracker-to-entity mapping file, tds.json, comes from DuckDuckGo's Tracker Radar project and can be found here: https://github.com/duckduckgo/tracker-blocklists/blob/main/web/tds.json. You can mod or grab the latest from them for your use case. 
