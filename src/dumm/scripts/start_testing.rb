br0 = Bridge.new("br0")
br1 = Bridge.new("br1")
br2 = Bridge.new("br2")

alice    = Guest["alice"]
venus    = Guest["venus"]
moon     = Guest["moon"]
carol    = Guest["carol"]
winnetou = Guest["winnetou"]
dave     = Guest["dave"]
sun      = Guest["sun"]
bob      = Guest["bob"]

alice.start
venus.start
moon.start
carol.start
winnetou.start
dave.start
sun.start
bob.start

alice.add("eth0").connect(br1).add("10.1.0.10")
venus.add("eth0").connect(br1).add("10.1.0.20")
moon.add("eth1").connect(br1).add("10.1.0.1")
moon.add("eth0").connect(br0).add("192.168.0.1")
carol.add("eth0").connect(br0).add("192.168.0.100")
winnetou.add("eth0").connect(br0).add("192.168.0.150")
dave.add("eth0").connect(br0).add("192.168.0.200")
sun.add("eth0").connect(br0).add("192.168.0.2")
sun.add("eth1").connect(br2).add("10.2.0.1")
bob.add("eth0").connect(br2).add("10.2.0.10")

alice.exec("ip route add dev eth0 10.1.0.0/16 src 10.1.0.10")
venus.exec("ip route add dev eth0 10.1.0.0/16 src 10.1.0.20")
moon.exec("ip route add dev eth1 10.1.0.0/16 src 10.1.0.1")
moon.exec("ip route add dev eth0 192.168.0.0/24 src 192.168.0.1")
carol.exec("ip route add dev eth0 192.168.0.0/24 src 192.168.0.100")
winnetou.exec("ip route add dev eth0 192.168.0.0/24 src 192.168.0.150")
dave.exec("ip route add dev eth0 192.168.0.0/24 src 192.168.0.200")
sun.exec("ip route add dev eth0 192.168.0.0/24 src 192.168.0.2")
sun.exec("ip route add dev eth1 10.2.0.0/16 src 10.2.0.1")
bob.exec("ip route add dev eth0 10.2.0.0/16 src 10.2.0.10")

alice.exec("ip route add default via 10.1.0.1")
venus.exec("ip route add default via 10.1.0.1")
moon.exec("ip route add default via 192.168.0.254")
carol.exec("ip route add default via 192.168.0.254")
winnetou.exec("ip route add default via 192.168.0.254")
dave.exec("ip route add default via 192.168.0.254")
sun.exec("ip route add default via 192.168.0.254")
bob.exec("ip route add default via 10.2.0.1")

moon.exec("echo 1 > /proc/sys/net/ipv4/ip_forward")
sun.exec("echo 1 > /proc/sys/net/ipv4/ip_forward")

