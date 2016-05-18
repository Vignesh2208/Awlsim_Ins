NUM_CORES := 4

CLEAN_EXPERIMENT = cd s3fnet-lxc/base/; bash CLEAN_EXPERIMENT

all: 
	echo "inc | rebuild | debuginc | debug"

inc: lxcman
	python awlsim/definitions.py
	cd s3fnet-lxc/base/; ./build.sh -i -n $(NUM_CORES)

rebuild: lxcman
	python awlsim/definitions.py
	cd s3fnet-lxc/base/; ./build.sh -f -n  $(NUM_CORES)
	
fullbuild: lxcman	
	python initialize.py
	python awlsim/definitions.py
	./create_sym_links.sh
	cd s3fnet-lxc/base/tklxcmngr/socket_hooks/; make clean; make;
	cd s3fnet-lxc/base/tklxcmngr/serial_driver/; make clean; make;
	cd s3fnet-lxc/base/tklxcmngr/virtual_time/; make clean; make;
	
	cd s3fnet-lxc/base/; ./build.sh -n $(NUM_CORES)

debuginc: lxcman
	python awlsim/definitions.py
	cd s3fnet-lxc/base/; ./build.sh -i -f -d -n $(NUM_CORES)

debug: lxcman
	python awlsim/definitions.py
	cd s3fnet-lxc/base/; ./build.sh -f -d -n $(NUM_CORES)

lxcman:	
	cd s3fnet-lxc/base/tklxcmngr; make clean; make;


clean_exp:
	$(CLEAN_EXPERIMENT)


	

