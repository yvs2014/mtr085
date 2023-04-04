MTR
---

mtr - a network diagnostic tool

SYNOPSIS
--------

**mtr \[-abBcdefFgimnopPqrsStuvwxyzZ46\] HOSTNAME ...**

DESCRIPTION
-----------

**mtr** combines the functionality of the **traceroute** and **ping** programs in a single network diagnostic tool.

As **mtr** starts, it investigates the network connection between the host **mtr** runs on and **HOSTNAME** by sending packets with purposely low TTLs. It continues to send packets with low TTL, noting the response time of the intervening routers. This allows **mtr** to print the response percentage and response times of the internet route to **HOSTNAME**. A sudden increase in packet loss or response time is often an indication of a bad (or simply overloaded) link.

The results are usually reported as round-trip-response times in miliseconds and the percentage of packetloss.

EXTRA
-------

- IDN (Internationalized Domain Names)
- Unicode (histograms)
- Ipinfo (additional information about hopes)
- Graphcairo (XCB/Xlib graphs)

DETAILS
-------
... *see mtr.8 page*

------------------------------------------------------------------------
SCREENSHOTS
-----------
## ipinfo
![ii-screenshot01](https://github.com/yvs2014/mtr/raw/master/img/ii-screenshot01.png)

## color/histogram
![ch-screenshot01](https://github.com/yvs2014/mtr/raw/master/img/ch-screenshot01.png)

## graphcairo
![gc-screenshot01](https://github.com/yvs2014/mtr/raw/master/img/gc-screenshot01.png)
![gc-screenshot02](https://github.com/yvs2014/mtr/raw/master/img/gc-screenshot02.png)
![gc-screenshot03](https://github.com/yvs2014/mtr/raw/master/img/gc-screenshot03.png)

