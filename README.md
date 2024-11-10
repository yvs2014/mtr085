MTR
---

mtr - a network diagnostic tool

SYNOPSIS
--------

**mtr \[-abBcdefFhilLmnNopqrsStTuvx46\] HOSTNAME ...**

DESCRIPTION
-----------

**mtr** combines the functionality of the **traceroute** and **ping** programs in a single network diagnostic tool.

As **mtr** starts, it investigates the network connection between the host **mtr** runs on and **HOSTNAME** by sending packets with purposely low TTLs. It continues to send packets with low TTL, noting the response time of the intervening routers. This allows **mtr** to print the response percentage and response times of the internet route to **HOSTNAME**. A sudden increase in packet loss or response time is often an indication of a bad (or simply overloaded) link.

The results are usually reported as round-trip-response times in miliseconds and the percentage of packetloss.

EXTRA
-------

- Unicode histograms
- Internationalized Domain Names
- Additional IP address information

DETAILS
-------
... *see mtr.8 page*

DEB PACKAGES
-----------
Built at [Launchpad](https://ppa.launchpadcontent.net/lrou2014/mtr085/ubuntu/pool/main/m/mtr085/)

------------------------------------------------------------------------
SCREENSHOTS
-----------
## ipinfo and IDN
![ii-screenshot10](https://github.com/yvs2014/mtr085/blob/master/img/ii-screenshot10.png)

## histogram
![ch-screenshot02](https://github.com/yvs2014/mtr085/blob/master/img/ch-screenshot02.png)
![ch-screenshot01](https://github.com/yvs2014/mtr085/blob/master/img/ch-screenshot01.png)

