#ifndef __USERLIST_H
#define __USERLIST_H

#include "global.h"
#include "config.h"
#include "tools.h"

class CUserEntry
{
public:
	string username;
	string pass;
	string ident;
	string socksip;
	int socksport;
	int oident;
	string oidentident;
	string sockspass;
	string socksuser;
	vector<string> userip;
	vector<string> allowedip;
	vector<string> bannedip;
};

class CUserList
{
public:
	
	void AddUser(CUserEntry);	

	bool IsInList(string);	

	bool CheckPass(string, string, CUserEntry &);

	bool CheckIdent(string, string);
	
	bool CheckUserHost(string,CUserEntry);

	bool CheckAllowedHost(string,CUserEntry);

	bool CheckBannedHost(string,CUserEntry);

	bool CheckAllIps(string);

private:
vector<CUserEntry> userlist;
};

extern CUserList userlist;

#endif
