#ifndef __SRVLOOKUP_H__
#define __SRVLOOKUP_H__

typedef std::string appstr;
typedef std::vector<appstr> srvlist;
size_t srvlookup(const char *srvstr, srvlist *result);

#endif

