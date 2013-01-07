#include <stdio.h>
#if 0
#include <winsock2.h>
#include <windns.h>
#endif

#include <map>
#include <vector>
#include <string>

#include "srvlookup.h"

size_t srvlookup(const char *srvstr, srvlist *result)
{
#if 0
    PDNS_RECORD pDnsSrvRecord;
    DNS_STATUS status = DnsQuery_UTF8(srvstr, DNS_TYPE_SRV, DNS_QUERY_BYPASS_CACHE,
	    NULL, &pDnsSrvRecord, NULL);
    if (status != 0)
	return 0;
    char buffer[1024];
    PDNS_RECORD perRecord = pDnsSrvRecord;
    while (perRecord != NULL) {
	if (strcmp(srvstr, perRecord->pName) == 0) {
	    if (perRecord->wType == DNS_TYPE_SRV) {
		PDNS_SRV_DATA pSrvDat = &perRecord->Data.SRV;
		printf("%s:%d %d %d\n", 
			pSrvDat->pNameTarget,
			pSrvDat->wPort,
			pSrvDat->wPriority,
			pSrvDat->wWeight);
		sprintf(buffer, "%s:%d\n", pSrvDat->pNameTarget, pSrvDat->wPort);
		result->push_back(buffer);
	    }
	}
	perRecord = perRecord->pNext;
    }
    DnsRecordListFree(pDnsSrvRecord, DnsFreeRecordList);
    return result->size();
#endif
	result->push_back("talk.l.google.com:5223");
	return 1;
}

#if 0
int main(int argc, char *argv[])
{
    srvlist srvrecords;
    srvlookup("_xmpp-client._tcp.gmail.com", &srvrecords);
    return 0;
}
#endif
