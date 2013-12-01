#include "userlist.h"


	
void CUserList::AddUser(CUserEntry entry)
{
	if(!IsInList(entry.username))
	{
		userlist.push_back(entry);
	}
}

bool CUserList::IsInList(string name)
{
	for(int i=0; i < (int)userlist.size();i++)
	{
		if(userlist[i].username == name)
		{
			return true;
		}
	}
	return false;
}

bool CUserList::CheckPass(string user, string pass, CUserEntry &entry)
{		
	for(int i=0; i < (int)userlist.size();i++)
	{
		if(userlist[i].username == user)
		{
			if(userlist[i].pass == pass)
			{
				entry = userlist[i];
				return true;
			}
		}
	}
	return false;
}

bool CUserList::CheckIdent(string user, string ident)
{
	for(int i=0; i < (int)userlist.size();i++)
	{
		if(userlist[i].username == user)
		{			
			if(userlist[i].ident == "") return true; // no ident means no check
			if(userlist[i].ident == ident) return true;
		}
	}
	return false;
}

bool CUserList::CheckUserHost(string ip,CUserEntry entry)
{	
	if(entry.userip.size() == 0) return true; // no ipmask set == all ips
	for(int i=0;i < (int)entry.userip.size();i++)
	{
		if(MatchIp(entry.userip[i],ip)) return true;
	}
	return false;
}

bool CUserList::CheckAllowedHost(string ip,CUserEntry entry)
{
	if(entry.allowedip.size() == 0) return true; // no ipmask set == all ips
	for(int i=0;i < (int)entry.allowedip.size();i++)
	{
		if(MatchIp(entry.allowedip[i],ip)) return true;
	}
	return false;
}

bool CUserList::CheckBannedHost(string ip,CUserEntry entry)
{
	if(entry.bannedip.size() == 0) return false; // no ipmask set == all ips
	for(int i=0;i < (int)entry.bannedip.size();i++)
	{
		if(MatchIp(entry.bannedip[i],ip)) return true;
	}
	return false;
}

bool CUserList::CheckAllIps(string ip)
{
	for(int i=0; i < (int)userlist.size();i++)
	{
		if(userlist[i].userip.size() == 0) return true; // no ipmask set == all ips
		for(int k=0;k < (int)userlist[i].userip.size();i++)
		{
			if(MatchIp(userlist[i].userip[k],ip)) return true;
		}
	}
	return false;
}

