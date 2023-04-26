# HARryParser

<h1>Installation:</h1>
<ol>
  <li>Clone this repo</li>
<li>cd to repo, run 
<code>pip install .</code> </li>
</ol>
<h1>Examples:</h1>
<code>python3 harryparser.py myfile.har -p mydomain.com</code>
<p>
In this example, you are running the tool against the .har file you generated for a domain mydomain.com. 
</p>
<p>
The tracker-to-entity mapping file, tds.json, comes from DuckDuckGo's Tracker Radar project and can be found here: https://github.com/duckduckgo/tracker-blocklists/blob/main/web/tds.json. You can mod or grab the latest from them for your use case. 
</p>
