herp re-writes ethernet headers, thereby acting as a user space bridge.
Right now, herp works on switched networks and forwards any packets that
have been sent to the host from ARP spoofing.

In the future, herp will probably become a real, although slow, bridge.


# EXPORTS

    start() -> {ok, PID}
    start(Device) -> {ok, PID}

        Types   Device = string()

        Device is the network interface name.


# HOW TO USE IT

    > herp:start(). % start up the bridge
    > farp:start().


# TODO

* test bridging between networks

* add a re-write IP header option

Although the target host may send data through the bridge to the gateway,
the gateway may respond directly to the target if the gateway's ARP
cache still holds the valid MAC address of the target. Force the gateway
to respond to the bridge by:

    * arp'ing an unused IP address with the bridge's MAC address

    * mapping the fake IP (and maybe a fake source port) to the target

    * re-write the source IP and port header from the response to the
      bridge's MAC address/gateway's IP address with the target's MAC/IP as
      the destination

The gateway will respond to the bridge's MAC address. The bridge OS
won't respond to the packets (e.g., send a RST) because the IP is not
bound to one of the host interfaces. herp will map the response to the
target host and re-write the MAC and IP headers.

Instead of looking up the map in an ets table or a data structure, state
could even be kept by having each source IP/port spawn a new process
(a gen_fsm) registered with the source IP/port.
