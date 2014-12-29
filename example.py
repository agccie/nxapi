#!/usr/bin/python

from nxapi_client import *
nxapi = NXAPIClient(hostname="clt-n9ka", username="varrow", password="ILoveVarrow!")
print nxapi.cli_show("show version")
print nxapi.cli_show_ascii("show system uptime")
nxapi.logout()
