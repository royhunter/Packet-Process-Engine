eth0=$(ifconfig eth0|grep RUNNING)
if [ "$eth0" == "" ];
then
	ifconfig pow0 down
else
	ifconfig pow0 up
fi

eth1=$(ifconfig eth1|grep RUNNING)
if [ "$eth1" == "" ];
then
	ifconfig pow1 down
else
	ifconfig pow1 up
fi

eth2=$(ifconfig eth2|grep RUNNING)
if [ "$eth2" == "" ];
then
	ifconfig pow2 down
else
	ifconfig pow2 up
fi

eth3=$(ifconfig eth3|grep RUNNING)
if [ "$eth3" == "" ];
then
	ifconfig pow3 down
else
	ifconfig pow3 up
fi