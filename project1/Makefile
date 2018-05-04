all: sucms_list

sucms_list: sucms_list.cpp SUCMS.h
	g++ sucms_list.cpp -lcrypto -lssl 

sucms_read: sucms_read.cpp SUCMS.h
	g++ sucms_read.cpp -lcrypto -lssl

sucms_delete: sucms_delete.cpp SUCMS.h
	g++ sucms_delete.cpp -lcrypto -lssl

sucms_write: sucms_write.cpp SUCMS.h
	g++ sucms_write.cpp -lcrypto -lssl
