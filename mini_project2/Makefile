all: udpchatmonitor udpchatclient udpchatserver

udpchatmonitor:
	g++ -o udpchatmon chat_monitor.cpp

udpchatclient:
	g++ -o udpchatcli chat_client.cpp

udpchatserver: UDPServer.h UDPServer.cpp chat_server.cpp UDPChatServer.h UDPChatServer.cpp ChatMonitor.h ChatMonitor.cpp ChatClient.h ChatClient.cpp
	g++ -o udpchatsrv UDPServer.cpp chat_server.cpp UDPChatServer.cpp ChatClient.cpp ChatMonitor.cpp
