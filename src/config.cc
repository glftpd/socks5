#include "config.h"
#include "tools.h"
#include "userlist.h"

CConfig::CConfig()
{
	// set some default values

	// section [DEBUG]
	debug = 1;
	debug_logfile = "socks5.log";	
	log_to_screen = 1;
	

	// section [CONNECTION]
	listen_port = 15000;	
	connect_ip = "";	
	listen_ip = "";
	listen_interface = "eth0";
	bind_port_start = 42000;
	bind_port_end = 46000;

	//section USER
	nr_users = 0;

	// section [LIMIT]
	day_limit = 0;
    week_limit = 0;
    month_limit = 0;

	
	ssl_ascii_cache = 0;

	// section [ADVANCED]
	oidentpath = "";
	oidentdelay=3;
	buffersize = 4096;
	pending = 10;
	connect_timeout = 7;
	ident_timeout = 5;
	read_write_timeout = 30;
	uid = 1;
	pidfile = "socks5.pid";
	retry_count = 5;
	no_ident_check = 0;
	use_ssl = 0;
	ssl_cert = "";
	no_chroot = 0;

}

CConfig::~CConfig()
{
}

string CConfig::getkey(string name,string data)
{
	string value = "ERROR";
	int start,end;
	string tmp = data;
	name = name + "=";
	start = tmp.find(name,0);
	if (start == (int)string::npos)
	{
		for (int i=0;i<(int)data.length();i++) { data[i] = '0'; }
		return value;
	}
	end = tmp.find(";",start);
	if (end == (int)string::npos)
	{
		for (int i=0;i<(int)data.length();i++) { data[i] = '0'; }
		return value;
	}
	value = tmp.substr(start + name.length(),end-start-name.length());
	for (int i=0;i<(int)data.length();i++) { data[i] = '0'; }
	
	return value;
}

// read conf entry of type string
void CConfig::getentry(string &i,string s,int &ok,string daten)
{
	string val;
	if ((val=getkey(s,daten)) != "ERROR")
   	{
   		i = val.c_str();
   	}
   	else
   	{
		cout << "using default value '" << i << "' for " << s << "\n";
   		//cout << s << " missing\n";
   		ok = 0;
   	}
}

// read conf entry of type int
void CConfig::getentry(int &i,string s,int &ok,string daten)
{
	string val;
	if ((val=getkey(s,daten)) != "ERROR")
   	{
   		i = atoi(val.c_str());
   	}
   	else
   	{
		i = 0;
		cout << "using default value '" << i << "' for " << s << "\n";
   		//cout << s << " missing\n";
   		ok = 0;
   	}
}

// read conf entry of type double
void CConfig::getentry(double &i,string s,int &ok, string daten)
{
	string val;
	if ((val=getkey(s,daten)) != "ERROR")
   	{
   		i = atof(val.c_str());
   	}
   	else
   	{
		cout << "using default value '" << i << "' for " << s << "\n";
   		//cout << s << " missing\n";
   		ok = 0;
   	}
}

int CConfig::readconf(string filename,string key,int crypted)
{
	int s;
	if (!filesize(filename,s))
	{
		cout << "Could not find config file!\n";
		return 0;
	}
	else
	{	
		unsigned char *bufferin,*bufferout;
		
		bufferout = new unsigned char [s+1];
		
		memset(bufferout,'\0',s+1);
		readfile(filename,&bufferin,s);
		
		string daten; // store uncrypted conf file
		
		if (crypted)
		{
			decrypt(key,bufferin,bufferout,s);
			daten = (char*)bufferout;
			memset(bufferin,'\0',s+1);
			memset(bufferout,'\0',s+1);
			delete [] bufferin;
	 		delete [] bufferout;			
		}
		else
		{			
			daten = (char *)bufferin;
	    	memset(bufferin,'\0',s+1);
			memset(bufferout,'\0',s+1);
	    	delete [] bufferin;
	 		delete [] bufferout;
		}    
		
 		int ok = 1;	// store if all vars could be read
	 	
		// section [DEBUG
		getentry(debug,"debug",ok,daten);
		getentry(log_to_screen,"log_to_screen",ok,daten);
		getentry(debug_logfile,"debug_logfile",ok,daten);
		
		// section [CONNECTION]
		getentry(listen_port,"listen_port",ok,daten);		
		getentry(connect_ip,"connect_ip",ok,daten);		
		getentry(listen_ip,"listen_ip",ok,daten);
		getentry(listen_interface,"listen_interface",ok,daten);
		getentry(bind_port_start,"bind_port_start",ok,daten);
		getentry(bind_port_end,"bind_port_end",ok,daten);
		
		//section USER
		getentry(nr_users,"nr_users",ok,daten);

		//read users
		for(int i=0;i < nr_users;i++)
		{
			stringstream ss;
			ss << (i+1);			
			string user,pass,ident,socksip,sockspass,socksuser,userip,allowedip,bannedip,oidentident;
			int socksport, oident;

			getentry(user,"USER" + ss.str(),ok,daten);
			getentry(pass,"PASS" + ss.str(),ok,daten);
			getentry(ident,"IDENT" + ss.str(),ok,daten);
			getentry(socksip,"SOCKSIP" + ss.str(),ok,daten);
			getentry(sockspass,"SOCKSPASS" + ss.str(),ok,daten);
			getentry(socksuser,"SOCKSUSER" + ss.str(),ok,daten);
			getentry(socksport,"SOCKSPORT" + ss.str(),ok,daten);
			getentry(userip,"USERIP" + ss.str(),ok,daten);
			getentry(allowedip,"ALLOWEDIP" + ss.str(),ok,daten);
			getentry(bannedip,"BANNEDIP" + ss.str(),ok,daten);
			getentry(oident,"OIDENT" + ss.str(),ok,daten);
			getentry(oidentident,"OIDENTIDENT" + ss.str(),ok,daten);
			CUserEntry entry;
			entry.username = user;
			entry.pass = pass;	
			entry.ident = ident;
			entry.socksip = socksip;
			entry.socksport = socksport;
			entry.socksuser = socksuser;
			entry.sockspass = sockspass;
			entry.oident = oident;
			entry.oidentident = oidentident;
			Split(userip,",",entry.userip,false);
			Split(allowedip,",",entry.allowedip,false);
			Split(bannedip,",",entry.bannedip,false);
			userlist.AddUser(entry);			
		}

		// section [LIMIT]
		getentry(day_limit,"day_limit",ok,daten);
		getentry(week_limit,"week_limit",ok,daten);
		getentry(month_limit,"month_limit",ok,daten);


		// section [ADVANCED]



		getentry(oidentpath,"oidentpath",ok,daten);
		getentry(oidentdelay,"oidentdelay",ok,daten);
		getentry(buffersize,"buffersize",ok,daten);
		getentry(pending,"pending",ok,daten);
		getentry(connect_timeout,"connect_timeout",ok,daten);
		getentry(ident_timeout,"ident_timeout",ok,daten);
		getentry(read_write_timeout,"read_write_timeout",ok,daten);
		getentry(uid,"uid",ok,daten);
		getentry(pidfile,"pidfile",ok,daten);
		getentry(retry_count,"retry_count",ok,daten);
		getentry(no_ident_check,"no_ident_check",ok,daten);
		getentry(use_ssl,"use_ssl",ok,daten);
		getentry(ssl_cert,"ssl_cert",ok,daten);
		getentry(no_chroot,"no_chroot",ok,daten);

   		for(int i=0;i < (int)daten.length();i++)
   		{
   			daten[i] = '0';
   		}
		return 1;
 		//if (ok == 1) return 1;
 		//else return 0;
	}

}
