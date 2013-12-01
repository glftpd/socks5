#ifndef __CONFIG_H
#define __CONFIG_H

#include "global.h"



class CConfig
{
	private:
	
	string getkey(string, string);
	void getentry(string &,string,int&,string);
	void getentry(int &,string,int&,string);
	void getentry(double &,string,int&,string);

	public:
	
	CConfig();
	
	~CConfig();
		
	int readconf(string, string, int);
	
	// config vars start here

	// section [DEBUG]
	int debug;
	int log_to_screen;
	string debug_logfile;
	
	// section [CONNECTION]
	int listen_port;
	string connect_ip;
	string listen_ip;
	string listen_interface;
	int bind_port_start;
	int bind_port_end;

	//section USER
	int nr_users;




	int ssl_ascii_cache;

	// section [LIMIT]
	double day_limit;
    double week_limit;
    double month_limit;



	// section [ADVANCED]
	
	int buffersize;
	int pending;	
	int connect_timeout;
	int ident_timeout;
	int read_write_timeout;
	int uid;	
	string pidfile;
	int retry_count;	
	

};

extern CConfig config;

#endif

