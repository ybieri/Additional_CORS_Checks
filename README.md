# Burp Extension: CORS* - Additional CORS Checks
## Description
This extension can be used to test websites for CORS misconfigurations. 
It can spot trivial misconfigurations like arbitrary origin reflection, but also more sublte ones where a regex is not properly configured (e.g. www.victim.com.attacker.com).
An issue is created if a dangeours origin is reflected. If `Access-Control-Allow-Credentials: true` is also set, the issue is rated high, otherwise low. Finally, the user has to decide whether the reflected Origin is intended (e.g. CDN) or whether it is a security issue.

## Features
`CORS* - Additional CORS Checks` can be run in either `automatic` or `manual` mode.

### Automatic
* In the `CORS*` tab, the extension can be activated.
* If activated, the extension will test CORS misconfigurations for each proxy request by sending multiple requests with different origins.
* There are options to only endable it for in-scope items and to exclude requests with certain file extensions.
* The `URL for CORS Request` is used to test for arbitrary reflection and as prefix/suffix in testing regex misconfigurations.

![Arbitrary origin reflected](https://github.com/ybieri/Additional_CORS_Checks/blob/master/doc/arbitrary_origin.png)

* If a potential misconfiguration is discovered, the request is highlighted in red (see request #3 above). 
* The request here does reflect the `null` origin and has `Access-Control-Allow-Credentials: true` set.

![Null origin reflected](https://github.com/ybieri/Additional_CORS_Checks/blob/master/doc/null_origin.png)

* If an issue is detected, it is also reported in the `Target` and `Dashboard` tabs.

![Issue](https://github.com/ybieri/Additional_CORS_Checks/blob/master/doc/issue.png)

### Manual
* Requests can be added to `CORS*` using the extension menu.

![Add to cors*](https://github.com/ybieri/Additional_CORS_Checks/blob/master/doc/add_to_corsair.png)

* The requests to test for CORS misconfiguration can then be sent using the `Send CORS requests for selected entry` button.

![Send requests](https://github.com/ybieri/Additional_CORS_Checks/blob/master/doc/send_requests.png)

## Installation
To install `CORS* - Additional CORS Checks` use the BApp Store. Open Burp and navigate to the `Extender` tab, then to the `BApp Store` tab. Select `CORS*` and hit the `Install` button to install the extension.

## Author
* Yves Bieri (Github: [ybieri](https://github.com/ybieri), Twitter: [yves_bieri](https://twitter.com/yves_bieri))

## Credits
Thanks to https://github.com/chenjj/CORScanner for the inspiration and https://github.com/portswigger/bookmarks for the Burp template.
