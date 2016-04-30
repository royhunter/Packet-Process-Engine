#/bin/sh

PROG_SECD="secd-linux_64" 

PROG_CLI="bin/cli"
PROG_SRV="bin/srv"

action=$1
argc=$#

clean_up()
{
	echo "clean_up"
	rm -rf sec-fw.tar.gz
	rm -rf secd-linux_64
	rm -rf ./bin
	rm -rf ./obj-linux_64-octeon3
	cd ./mgrplane
	rm src/client/cparser_tree.c
	rm src/client/cparser_tree.h
	make clean
	exit
}

build_dataplane(){
	echo "---------------------------------------------------"
	echo "+                                                 +"
	echo "+            Sec Fw Dataplane                     +"
	echo "+                                                 +"
	echo "---------------------------------------------------"

	rm -f $PROG_SECD
	make OCTEON_TARGET=linux_64
	if [ $? -eq 0 ]; then
		echo "Dataplane build done!"
	else
		echo "Error! Dataplane build failed!"
		exit 
	fi

	if [ ! -f "$PROG_SECD" ]; then
		echo "$PROG_SECD not exist"
		exit 
	fi

	cp $PROG_SECD bin/
	echo "Dataplane build success....."
}

build_mgrplane(){
	echo "---------------------------------------------------"
	echo "+                                                 +"
	echo "+            Sec Fw Mgrplane                      +"
	echo "+                                                 +"
	echo "---------------------------------------------------"

	cd ./mgrplane 

	rm -rf bin
	pwd
	make

	if [ $? -eq 0 ]; then
		echo "Mgrplane build done!"
	else
		echo "Error! Mgrplane build failed!"
	fi


	if [ ! -f "$PROG_CLI" ]; then
		echo "$PROG_CLI not exist" 
		exit
	fi

	if [ ! -f "$PROG_SRV" ]; then
		echo "$PROG_SRV not exist"
		exit
	fi

	cp $PROG_CLI ../bin/
	cp $PROG_SRV ../bin/

	echo "Mgrplane build success....."
	cd ..
}

build_all(){
	echo "build_all"
	build_dataplane
	build_mgrplane
}

prog_build_check(){
	if [ ! -f "bin/secd-linux_64" ]; then
		echo "bin/secd-linux_64 not exist"
		exit 
	else
		echo "bin/secd-linux_64 ok!"
	fi

	if [ ! -f "bin/cli" ]; then
		echo "bin/cli not exist" 
		exit
	else
		echo "bin/cli ok!"
	fi

	if [ ! -f "bin/srv" ]; then
		echo "bin/srv not exist"
		exit
	else
		echo "bin/srv ok!"
	fi
}


build_start(){

	if [ ! -d bin ]; then
		mkdir bin
	fi
	
	if [ $argc -gt 0 ]; then
		if [ $action = "clean" ]; then
			clean_up	
		elif [ $action = 'dataplane' ]; then
			build_dataplane
		elif [ $action = 'mgrplane' ]; then
			build_mgrplane
		fi
	else
		build_all
	fi

}

make_package(){
	cp version/scripts/startup.sh bin/
	cp version/scripts/netstat_monitor.sh bin/
	tar czf sec-fw.tar.gz bin
	if [ $? -eq 0 ]; then
		echo "Package make ok!"
	else
		echo "Error! Package make failed!"
	fi
}


build_start

prog_build_check

make_package







