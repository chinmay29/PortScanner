
PortScanner : PortScanner.cpp Scanner_lib.cpp MultiThread.cpp PortScanner.h Scanner_lib.h MultiThread.h 
		g++ MultiThread.cpp Scanner_lib.cpp PortScanner.cpp -o PortScanner -pthread	

.PHONY : clean
clean :
	rm -f ./PortScanner
