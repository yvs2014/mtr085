MTR
---

mtr - a network diagnostic tool

SYNOPSIS
--------

**mtr \[-46abBcdefFhilLmMnNopqrsStTuvx\] TARGET[:PORT] ...**

DESCRIPTION
-----------

**mtr** combines the functionality of the **traceroute** and **ping** programs in a single network diagnostic tool.

As **mtr** starts, it investigates the network connection between the host **mtr** runs on and **TARGET** by sending packets with purposely low TTLs. It continues to send packets with low TTL, noting the response time of the intervening routers. This allows **mtr** to print the response percentage and response times of the internet route to **TARGET**.

EXTRA
-------

- Unicode histograms
- Native Language Support
- Internationalized Domain Names
- Additional IP address information

DETAILS
-------
... *see mtr.8 page*

------------------------------------------------------------------------
SCREENSHOTS
-----------
## ipinfo and IDN
![ii-screenshot10](https://github.com/yvs2014/mtr085/blob/master/img/ii-screenshot10.png)

## histogram
![ch-screenshot02](https://github.com/yvs2014/mtr085/blob/master/img/ch-screenshot02.png)
![ch-screenshot01](https://github.com/yvs2014/mtr085/blob/master/img/ch-screenshot01.png)

