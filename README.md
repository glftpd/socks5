Simple Socks5 v0.9.6 (c) _hawk_/PPX

How to compile
----------------------
Just type 'make clean linux'
Needs g++ and openssl + header files

How to setup
-------------------
Copy socks5.conf.dist to bin/socks5.conf and edit

How to start
-----------------
To start with uncrypted conf: ./socks5 -u socks5.conf
To start with crypted conf: ./socks5 socks5.conf
To encrypt the conf use the blowcrypt tool in bin

Parameters in conf file
--------------------------------

[ Debug ]
debug=0; - turn debugging on/off
log_to_screen=1; - print debug msgs to screen or to file
debug_logfile=log.txt; - debug logfilename

[ Connection ]
listen_port=123; - listen port
connect_ip=; - bind to special ip when connecting
listen_ip=; - bind to special ip when listening
listen_interface=eth0; - interface to get ip from if listen_ip is not specified
bind_port_start=40000; - port range used for bind method
bind_port_end=45000;

[ User ]
nr_users=1; - how many users in conf file
USER1=hawk; - username
PASS1=test; - userpass
IDENT1=hawk; - if specified user must have this ident
SOCKSIP1=; - if specified socks5 uses another socks5 to conenct to target - specify login options below
SOCKSPORT1=;
SOCKSPASS1=;
SOCKSUSER1=;
USERIP1=; - if specified user must have this ip(s) - can use ? and * but not - (ranges) - list of ips seperated with ,
ALLOWEDIP1=; - if specified socks5 will only connect to this ips
BANNEDIP1=; - if specified this target ips are not allowed
OIDENT1=1; - 1 to enable oidentd feature - 0 to disable
OIDENTIDENT1=; - use this ident with oidentd every time (else users ident is used)

change options below only if you know what you're doing

[ Limit ]
day_limit=0; 
week_limit=0;
month_limit=0;

[ Advanced ]
oidentpath=/home/hawk/.oidentd.conf; - if you want to use oidentd spoofing enter path to users .oidentd.conf file including filename here
oidentdelay=3; - delay in seconds before restoring old .oidentd.conf - 0 if you want it not restored
buffersize=4096;
pending=50;
connect_timeout=7;
ident_timeout=5;
read_write_timeout=30;
uid=1;
pidfile=socks5.pid;
retry_count=10;
no_ident_check=0; - if enabled no ident request is made - dynamic ident with oidentd wont work

-----------------------------------------------------------------------------------------------
