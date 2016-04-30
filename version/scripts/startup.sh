chmod -R 777 secd-linux_64 cli srv

modprobe octeon-pow-ethernet receive_group=1 broadcast_groups=4 ptp_rx_group=14 ptp_tx_group=13


ifconfig eth0 promisc up
ifconfig eth1 promisc up
ifconfig eth3 promisc up
ifconfig eth2 promisc up

ifconfig pow0 down
ifconfig pow1 down
ifconfig pow2 down
ifconfig pow3 down




