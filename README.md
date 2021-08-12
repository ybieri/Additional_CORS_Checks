# Burp Extension: CORSair
## Description
This extension can be used to test websites for CORS misconfigurations.It was written to speed-up testing of CORS misconfigurations and to not miss more tricky misconfigurations.
It can spot trivial misconfigurations like arbitrary origin reflection, but also more sublte ones where a regex is not properly configured.

## Features
CORSair has two modes to detect CORS misconfigurations: automatic and manual.

### Automatic
* In the CORSair tab, the extension can be activated.
* If activated, the extension will test CORS misconfigurations for each proxy request by sending multiple requests with different origins.
* There are options to only endable it for in-scope items and to exclude requests with certain file extensions.
* The `URL for CORS Request` is used to test for arbitrary reflection and as prefix/suffix in testing regex misconfigurations.

![Arbitrary origin reflected](https://github.com/ybieri/CORSair/blob/master/doc/arbitrary_origin.png)

* If a potential misconfiguration is discovered, the request is highlighted in red (see request #3 above). 
* The request here does reflect the `null` origin and has `Access-Control-Allow-Credentials: true` set.

![Null origin reflected](https://github.com/ybieri/CORSair/blob/master/doc/null_origin.png)

* If an issue is detected, it is also reported in `Target` and `Dashboard` tabs.

![Issue](https://github.com/ybieri/CORSair/blob/master/doc/issue.png)

### Manual
* Requests can be added to CORSair using the extension menu.

![Add to corsair](https://github.com/ybieri/CORSair/blob/master/doc/add_to_corsair.png)

* The requests to test for CORS misconfiguration can then be sent using the `Send CORS requests for selected entry` button.

![Send requests](https://github.com/ybieri/CORSair/blob/master/doc/send_requests.png)

## Installation
### Manual Installation
Start Burp and navigate to the `Extender` tab, `Extensions`, `Add`. Choose the `CORSair` JAR file to install the extension.

### Installation from BApp Store
The easy way to install CORSair is using the BApp Store. Open Burp and navigate to the `Extender` tab, then to the` BApp Store` tab. Select `CORSair` and hit the `Install` button to install the extension.

## Author
* Yves Bieri (Github: [ybieri](https://github.com/ybieri), Twitter: [yves_bieri](https://twitter.com/yves_bieri))
