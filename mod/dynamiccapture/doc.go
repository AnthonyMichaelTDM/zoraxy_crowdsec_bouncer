/*
This module contains the dynamic sniff and capture handler implementations.

The sniff handler is called by zoraxy for every request and is responsible for determining whether a request should be accepted or skipped.
It directly interacts with the CrowdSec bouncer to check if the request IP is banned or not.

  - If accepted, the request will be forwarded to the capture handler by zoraxy, which will handle blocking the request (presenting a forbidden page, captcha, etc).
  - If skipped, zoraxy will forward the request to the next handler in the chain, which could be the origin server or another plugin.

The capture handler is where zoraxy directs the requests that were accepted by the sniff handler.
It is responsible for handling the request, which in this case means blocking the request or eventually maybe presenting a captcha.

For more information, refer to the [zoraxy documentation on plugin architecture](https://zoraxy.aroz.org/plugins/html/2.%20Architecture/1.%20Plugin%20Architecture.html).
*/
package dynamiccapture
