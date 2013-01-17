#ifndef __SRVLOOKUP_H__
#define __SRVLOOKUP_H__

typedef std::string appstr;
typedef std::vector<appstr> srvlist;
int srvlookup(const char *srvstr, srvlist *result);

#endif

