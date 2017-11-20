Halflife t<sub>½</sub>
================

This is a simple back-end client to help analyze new Smoke Detector hits.

The first iteration looks for URLs in the reported posts and checks whether
the domain is already blacklisted, and whether we have seen it in Metasmoke
before.

Down the line, I hope to be able to enable automatic blacklisting when a
domain name passes the criteria we have for updating the blacklists.

Results are currently logged to a websocket on
`ws://ec2-52-208-37-129.eu-west-1.compute.amazonaws.com:8888`
and relayed by the PulseMonitor bot in the chat room
[Charcoal Test](https://chat.stackexchange.com/rooms/65945/charcoal-test).


Configuration
-----------

You will need to have `requests` and `websocket-client` installed, perhaps in
a virtual environment.

    python3 -m venv halflife-env
    . ./halflife-env/bin/activate
    pip install -r requirements.txt

Create a file `halflife.conf` containing a JSON representation of your
Metasmoke API key.

    {"metasmoke-key": "01234deadbeef....78abcdef"}

Check out a copy of the SmokeDetector `git` project in a separate
directory (for the blacklists) and run it there.
The following assumes you have SmokeDetector in a sibling directory
of the one where you have checked out `halflife`.

	cd ../SmokeDetector
	ln -s ../halflife/halflife.conf .
    ../halflife/halflife.py


Hacking
-------

For quick testing, the script `nst.py` can be used to run Halflife
on a set of JSON results from Metasmoke.

    $ curl -s -o output.json 'https://metasmoke.erwaysoftware.com/search.json'

    $ ./nst.py output.json

You can use any search you like; the regular Metasmoke search page
returns a link to the same results in JSON format in the footer.
(The operative difference is to use the URL path `/search.json` instead
of just `/search`).
The default search simply returns the latest 100 posts
which were archived by Metasmoke (including any false positives).


Docker Image
------------

There is a `Dockerfile` here which creates a runnable image for trying
this out.

https://hub.docker.com/r/tripleee/halflife/

The Docker image exposes its output on a websocket on port 8888.

*The websocket output format is totally ad hoc and **will** change.*
