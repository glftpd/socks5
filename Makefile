CPPFLAGS = -W -Wall -g -I/usr/local/ssl/include -Iinclude

.cc.o   :
	 g++ -c $(CPPFLAGS) $< -o $@

all:
	@echo "To compile socks5 type"
	@echo "  - 'make linux' to compile under linux"
	@echo "  - or 'make clean'"

linux: src/socks5.o src/counter.o src/config.o src/tools.o src/lock.o src/blowcrypt.o src/userlist.o
	g++ src/blowcrypt.o src/config.o src/lock.o src/counter.o src/tools.o src/userlist.o -o bin/blowcrypt -lssl -lcrypto -lpthread; strip bin/blowcrypt
	g++ src/socks5.o src/config.o src/lock.o src/counter.o src/tools.o src/userlist.o -o bin/socks5 -lssl -lcrypto -lpthread; strip bin/socks5

linux-static: src/socks5.o src/counter.o src/config.o src/tools.o src/lock.o src/blowcrypt.o src/userlist.o
	g++ -static src/blowcrypt.o src/config.o src/lock.o src/counter.o src/tools.o src/userlist.o -o bin/blowcrypt-static -lssl -lcrypto -lpthread -lz -ldl; strip bin/blowcrypt-static
	g++ -static src/socks5.o src/config.o src/lock.o src/counter.o src/tools.o src/userlist.o -o bin/socks5-static -lssl -lcrypto -lpthread -lz -ldl; strip bin/socks5-static
                
                
  
clean:
	@(rm -f bin/socks5 bin/blowcrypt bin/socks5-static bin/blowcrypt-static src/*.o)
	@(echo "Clean succesful")
