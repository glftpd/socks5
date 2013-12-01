#ifndef __GLOBAL_H
#define __GLOBAL_H
#define _MULTI_THREADED
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <fstream>
#include <pthread.h>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cctype>
#include <list>
#include <iomanip>
#include <syslog.h>


using namespace std;

#define version "Simple Socks5 v0.9.5 (c) _hawk_/PPX"
#define builddate "20.03.2007"

#if defined(__GNUC__) && __GNUC__ < 3
#define ios_base ios
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#ifndef SIOCGIFADDR
#include <sys/sockio.h>
#endif

#ifndef PATH_DEVNULL
#define PATH_DEVNULL "/dev/null"
#endif

#endif

