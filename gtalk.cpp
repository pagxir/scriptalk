#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <string>
#include <vector>
#include <map>

#include "parser.h"
#include "tinyxml.h"
#include "srvlookup.h"

#define BUFSIZE 65536
typedef unsigned char uint8_t;
const char *LOG_TAG = "UNKOWN";

struct xmpp_struct {
    const char *user;
    const char *domain;
    const char *resource;
    const char *password;
	
    size_t available;
    char buffer[BUFSIZE + 1];

	struct xml_upp parser;
};

struct tiny_event {
	int id;
};

char *itoa(int a, char *buf, int len)
{
	snprintf(buf, len, "%d", a);
	return buf;
}

tiny_event *create_tiny_event(void)
{
	return NULL;
}

int wait_for_event(tiny_event *event, int timeout)
{
	return 0;
}

int close_event(tiny_event *event)
{
	return 0;
}

static int fill_buffer(struct xmpp_struct *up, BIO *iop)
{
	int len;
	char *buf = up->buffer;
	size_t avail = up->available;

	assert(BUFSIZE > avail);
	len = BIO_read(iop, buf + avail, BUFSIZE - avail);
	if (len == 0) {
		fprintf(stderr, "BIO_read error\n");
		return -1;
	}

	if (len == -1) {
		fprintf(stderr, "BIO_read failure\n");
		return -1;
	}

	buf[avail + len] = 0;
	up->available = (avail + len);
	fprintf(stderr, "[%s] %s\n", LOG_TAG, buf + avail);
	return 0;
}

static void xmpp_write(const void *buff, size_t count);

static char *strsplit(char *str, char chr)
{
    char *p = NULL;
    if (str == NULL)
		return NULL;
    p = strchr(str, chr);
    if (p != NULL)
       	*p++ = 0;
    return p;
}

static SSL_CTX *xmpp_tlsctx()
{
    static SSL_CTX *_sslctx = NULL;
    if (_sslctx == NULL)
		_sslctx = SSL_CTX_new(TLSv1_client_method());
    return _sslctx;
}

static char str2b64[256];
static char b64tostr[65]={
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

void base64init()
{
    int i, idx;
    memset(str2b64, 0xFF, sizeof(str2b64));
    for (i=0; i<64; i++) {
		idx = b64tostr[i];
		str2b64[idx] = i;
    }
    str2b64[int('=')] = 0;
}

size_t base64dec(const char ** inptr, void *buffer, size_t bufsz)
{
    size_t bitbuf=0, bitcnt=0;
    const char *ptext = *inptr;
    char *pbuff = (char*)buffer;
	
    while (*ptext != 0) {
		size_t bitval = *ptext++;
		assert(bitval < 256);
		if (str2b64[bitval]==-1)
			continue;
		
		bitbuf = (bitbuf<<6)|str2b64[bitval];
		bitcnt += 6;
		
		while (bitcnt >= 8) {
			if (bufsz == 0) {
				*inptr = ptext;
				return pbuff-(char*)buffer;
			}
			bufsz --;
			bitcnt -= 8;
			*pbuff++ = bitbuf>>bitcnt;
		}
		
		if (bitval == '=') {
			break;
		}
    }
    *inptr = ptext;
    return pbuff-(char*)buffer;
}

static appstr bin2B64str(const char *mem, size_t count)
{
    int i;
    int out = 0;
    char buff[8192];
	
    size_t bitcnt = 0;
    size_t bitvalues = 0;
	
    uint8_t *text = (uint8_t*)mem;
    for (i=0; i<int(count); i++){
        bitvalues <<= 8;
        bitvalues |= text[i];
        bitcnt += 8;
		
        while (bitcnt>6){
            int ch = 0x3F&(bitvalues>>(bitcnt-6));
            buff[out++] = b64tostr[ch];
            bitcnt -= 6;
        }
    }
	
    if (bitcnt > 0){
        int ch = 0x3F&(bitvalues<<(6-bitcnt));
        buff[out++] = b64tostr[ch];
        bitcnt -= 6;
    }
	
    while (out&0x3){
        buff[out] = '=';
        out++;
    }
    buff[out] = 0;
    return buff;
}

static appstr xmpp_handshake(const char *domain)
{
    appstr handshake;
    handshake = "<stream:stream to='";
    handshake += domain;
    handshake += "' xmlns='jabber:client' xmlns:stream=";
    handshake += "'http://etherx.jabber.org/streams' version='1.0'>";
    return handshake;
}

static appstr xmpp_starttls()
{
    appstr starttls; 
    starttls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
    return starttls;
}

static int xmpp_seek_handshake(struct xmpp_struct *xmppdat)
{
    char *p = xmppdat->buffer;
    char *p_end = &p[xmppdat->available];

	*p_end = 0;
	xmppdat->parser.error = 0;
	p = (char *)tag_begin(&xmppdat->parser, p);

	if (xmppdat->parser.error == 0) {
		xmppdat->available = p_end - p;
		memmove(xmppdat->buffer, p, p_end - p + 1);
		return 0;
	}

    return -1;
}

static int proxy_seek_handshake(struct xmpp_struct *xmppdat)
{
	char *s;
    char *p = xmppdat->buffer;

	s = strstr(p, "\r\n\r\n");
	if (s != NULL) {
		s += 4;
		xmppdat->available = (s - p);
		memmove(xmppdat->buffer, s, s - p + 1);
		return 0;
	}

    return -1;
}

static int proxy_read_handshake(BIO *bio, struct xmpp_struct *xmppdat)
{
	LOG_TAG = "PROXY-RX";

    do {
		if (fill_buffer(xmppdat, bio) != 0)
			return -1;
    } while (proxy_seek_handshake(xmppdat));

    return 0;
}

static int xmpp_read_handshake(BIO *bio, struct xmpp_struct *xmppdat)
{
	LOG_TAG = "TRACE-RX";

    do {
		if (fill_buffer(xmppdat, bio) != 0)
			return -1;
    } while (xmpp_seek_handshake(xmppdat));

    return 0;
}

static BIO *g_xmpp_bio = NULL;

static void dump(const char *p, size_t count)
{
    printf("------------------\n");
    fwrite(p, count, 1, stdout);
    printf("\n------------------\n");
}

static int xmpp_read_packet(BIO *bio, struct xmpp_struct *xmppdat, TiXmlElement *packet)
{
    int count = 0;
    const char *p = NULL;
    assert(xmppdat != NULL);
    char *buffer = xmppdat->buffer;
	
    TiXmlElement parser("");
    p = parser.Parse(buffer, NULL, TIXML_ENCODING_UTF8);
    if (p == NULL)
        goto fill_buffer;
    *packet = parser;
    assert (xmppdat->available <= BUFSIZE);
    xmppdat->available -= (p-buffer);
    memmove(buffer, p, xmppdat->available+1);
    return 0;
	
fill_buffer:
    for (;;) {
       	TiXmlElement parser("");
		size_t available = xmppdat->available;
		assert (available < BUFSIZE);
        count = BIO_read(bio, buffer+available, BUFSIZE-available);
        if (count == 0) {
			int code = errno;
			dump(buffer, available);
            return -1;
		}
		if (count == -1) {
			int code = errno;
			dump(buffer, available);
			return -1;
		}
        available += count;
        buffer[available] = ' ';
        buffer[available + 1] = 0;
		assert (available <= BUFSIZE);
		xmppdat->available = available;

        p = parser.Parse(buffer, NULL, TIXML_ENCODING_UTF8);
		printf("LINE failure: %p\n", p);
		parser.Print(stderr, -1);
        if (p == NULL)
            continue;
		printf("LINE success: %p\n", p);
		*packet = parser;
        available -= (p-buffer);
		assert (available <= BUFSIZE);
		xmppdat->available = available;
        memmove(buffer, p, available+1);
        return 0;
    }
    return -1;
}

static int xmpp_tls_stage(BIO *bio, struct xmpp_struct *xmppdat)
{
    appstr handshake = xmpp_handshake(xmppdat->domain);
    size_t count = BIO_write(bio, handshake.c_str(), handshake.size());
    assert(count == handshake.size());
	
    xmppdat->available = 0;
    if (xmpp_read_handshake(bio, xmppdat) != 0) {
		assert(0);
		return -1;
    }
	
	printf("L\n");
    TiXmlElement packet("");
    if (xmpp_read_packet(bio, xmppdat, &packet) != 0) {
		assert(0);
		return -1;
    }
	printf("LO\n");
	
    appstr starttls = xmpp_starttls();
    count = BIO_write(bio, starttls.c_str(), starttls.size());
    assert(count == starttls.size());
	
    TiXmlElement proceed("");
	printf("LL\n");
    if (xmpp_read_packet(bio, xmppdat, &proceed) != 0) {
		assert(0);
		return -1;
    }
    return 0;
}

static appstr xmpp_sasl(struct xmpp_struct *xmppdat)
{
    appstr sasl;
    char b64buff[1024];
    int count = sprintf(b64buff, "@%s@%s",
		xmppdat->user, xmppdat->password);
    b64buff[strlen(xmppdat->user)+1] = b64buff[0] = 0;
	
    sasl = "<auth mechanism='PLAIN' xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>";
    sasl += bin2B64str(b64buff, count);
    sasl += "</auth>'";
    return sasl;
}

static appstr xmpp_bind(struct xmpp_struct *xmppdat)
{
    appstr bind("<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>");
    if (xmppdat->resource && xmppdat->resource[0]) {
		bind =  "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>";
		bind += xmppdat->resource;
		bind += "</resource></bind>";
    }
    appstr reqbind = "<iq id='bind0' type='set'>";
    reqbind += bind;
    reqbind += "</iq>";
    return reqbind;
}

static appstr xmpp_session(struct xmpp_struct *xmppdat)
{
    appstr session;
    session = "<iq id='1' type='set'>";
    session += "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>";
    session += "</iq>";
    return session;
}

static int xmpp_sasl_stage(BIO *bio, struct xmpp_struct *xmppdat)
{
    appstr handshake = xmpp_handshake(xmppdat->domain);
    size_t count = BIO_write(bio, handshake.c_str(), handshake.size());
    assert(count == handshake.size());
	
    xmppdat->available = 0;
    if (xmpp_read_handshake(bio, xmppdat) != 0) {
		assert(0);
		return -1;
    }
	
    TiXmlElement packet("");
    if (xmpp_read_packet(bio, xmppdat, &packet) != 0) {
		assert(0);
		return -1;
    }
	
    appstr sasl = xmpp_sasl(xmppdat);
    count = BIO_write(bio, sasl.c_str(), sasl.size());
    assert(count == sasl.size());
	
    TiXmlElement authresult("");
    if (xmpp_read_packet(bio, xmppdat, &authresult) != 0) {
		assert(0);
		return -1;
    }
    if (strcmp(authresult.Value(), "success")) {
		assert(0);
		return -1;
    }
    return 0;
}

static int bio_tls_set(BIO **bio)
{
    BIO *rawio = *bio;
    *bio = BIO_new_ssl(xmpp_tlsctx(), 1);
    BIO_push(*bio, rawio);
    if (BIO_do_handshake(*bio) <= 0) {
        printf("hand shake fail\n");
        return -1;
    }
    return 0;
}

static int xmpp_session_stage(BIO *bio, struct xmpp_struct *xmppdat)
{
    appstr handshake = xmpp_handshake(xmppdat->domain);
    size_t count = BIO_write(bio, handshake.c_str(), handshake.size());
    assert(count == handshake.size());
	
    if (xmpp_read_handshake(bio, xmppdat) != 0) {
		assert(0);
		return -1;
    }
	
    TiXmlElement packet("");
    if (xmpp_read_packet(bio, xmppdat, &packet) != 0) {
		assert(0);
		return -1;
    }
	
    appstr bind = xmpp_bind(xmppdat);
    count = BIO_write(bio, bind.c_str(), bind.size());
    assert(count == bind.size());
	
    TiXmlElement bindresult("");
    if (xmpp_read_packet(bio, xmppdat, &bindresult) != 0) {
		assert(0);
		return -1;
    }
    const char *jidText = NULL;
    TiXmlHandle hBindResult(&bindresult);
    TiXmlElement *jidNode = hBindResult.FirstChildElement("bind").
		FirstChildElement("jid").ToElement();
    if (jidNode!=NULL && (jidText=jidNode->GetText())) {
		printf("local client jid: %s\n", jidText);
    }
	
    appstr session = xmpp_session(xmppdat);
    count = BIO_write(bio, session.c_str(), session.size());
    assert(count == session.size());
	
    TiXmlElement sessresult("");
    if (xmpp_read_packet(bio, xmppdat, &sessresult) != 0) {
		assert(0);
		return -1;
    }
    return 0;
}

static appstr xmpp_presence()
{ 
    appstr presence("<presence>");
    presence += "<priority>1</priority>";
#if 0
    presence += "<show>dnd</show>";
#endif
    presence += "<status>Hello every one</status>";
#if 0
    presence += "<c node='http://pidgin.im/' hash='sha-1' ver='ZJcqUfuUIFo9PX0wTgU7J3kB5hA=' xmlns='http://jabber.org/protocol/caps' />";
#else
    presence += "<c node='http://www.google.com/xmpp/client/caps' ver='1.0.0.104' ";
    presence += " ext='share-v1 voice-v1' xmlns='http://jabber.org/protocol/caps' />";
#endif
    presence += "<x xmlns='vcard-temp:x:update'><photo>79bc9d4ea79a8c1f759f637462075d5fa2eda5fe</photo></x>";
    presence += "</presence>";
    return presence;
}

static int xmpp_online(BIO *bio)
{
    appstr presence =xmpp_presence();
    size_t count = BIO_write(bio, presence.c_str(), presence.size());
    assert(count == presence.size());
    return 0;
}

static int xmpp_message_stage(BIO *bio, struct xmpp_struct *xmppdat, TiXmlElement *message)
{
    TiXmlElement &packet = *message;
    TiXmlElement *xmlMsgBody = packet.FirstChildElement("body");
    if (xmlMsgBody == NULL) {
		return -1;
    }
    const char *msgBody = xmlMsgBody->GetText();
    printf("from %s message: %s\n",
		packet.Attribute("from"),
		msgBody);
    return 0;
}

class XmppPacket: public TiXmlElement
{
public:
	XmppPacket(const TiXmlElement &base);
	XmppPacket();
};

XmppPacket::XmppPacket()
:TiXmlElement("")
{
}

XmppPacket::XmppPacket(const TiXmlElement &base)
:TiXmlElement("")
{
    *dynamic_cast<TiXmlElement*>(this) = base;
}

static std::map<appstr, XmppPacket> g_online_users;
static std::map<appstr, XmppPacket> g_roster_users;

static int xmpp_presence_stage(BIO *bio, struct xmpp_struct *xmppdat, TiXmlElement *message)
{
    TiXmlElement &packet = *message;
    const char *type = packet.Attribute("type");
    if (type == NULL) {
		const char *from = packet.Attribute("from");
		assert(from != NULL);
		g_online_users[from] = XmppPacket(packet);
    } else if (!strcmp(type, "unavailable")) {
		const char *from = packet.Attribute("from");
		assert(from != NULL);
		g_online_users.erase(from);
    } else {
       	printf("%s: %s\n", type, packet.Attribute("from"));
    }
    return 0;
}

enum IqType{IQ_SET, IQ_GET, IQ_RESULT, IQ_ERROR, IQ_UNKOWN};

static IqType a2iqtype(const char *type)
{
    if (!strcmp(type, "set")) {
		return IQ_SET;
    } else if (!strcmp(type, "get")) {
		return IQ_GET;
    } else if (!strcmp(type, "result")) {
		return IQ_RESULT;
    } else if (!strcmp(type, "error")) {
		return IQ_ERROR;
    }
    assert(0);
    return IQ_UNKOWN;
}

struct IQInfo{
    int *hResult;
	tiny_event *hEvent;
    TiXmlElement *hPacket;
};

static std::map<appstr, IQInfo> g_iq_infos;

static appstr xmpp_attribute(const char *attrname, const char *attrval)
{
    appstr attribute(" ");
    if (attrval == NULL)
		return "";
    if (*attrval == 0)
		return "";
    attribute += attrname;
    attribute += "=";
    attribute += '\"';
    attribute += attrval;
    attribute += '\"';
    return attribute;
}

static appstr xmpp_result(const char *id,  const char *from, const char *payload)
{
    appstr text("<iq type='result'");
    text += xmpp_attribute("id", id);
    text += xmpp_attribute("to", from);
    if (payload == NULL)
		return text + "/>";
    text += ">";
    text += payload;
    text += "</iq>";
    return text;
}

static int do_iq_service(BIO *bio, struct xmpp_struct *xmppdat, TiXmlElement *message)
{
    TiXmlElement *payload;
    payload = message->FirstChildElement();
    const char *type = message->Attribute("type");
    const char *xmlns = payload->Attribute("xmlns");
    if (!strcmp(xmlns, "screen-snapshot")) {
		if (a2iqtype(type) == IQ_GET) {
			const char *id = message->Attribute("id");
			const char *from = message->Attribute("from");
			appstr response = xmpp_result(id, from, NULL);
			xmpp_write(response.c_str(), response.size());
		}
    }else if (!strcmp(xmlns, "stun-address")) {
#if 0
		if (a2iqtype(type) == IQ_GET) {
			const char *id = message->Attribute("id");
			const char *from = message->Attribute("from");
			appstr stun = appstr("<stun xmlns='stun-address' ");
			stun += xmpp_attribute("address", stun_address().c_str());
			stun += "/>";
			appstr response = xmpp_result(id, from, stun.c_str());
			xmpp_write(response.c_str(), response.size());
			stun_send(stun.c_str(), stun.size(), payload->Attribute("address"));
		}
#endif
    }
    return 0;
}

static int xmpp_iq_stage(BIO *bio, struct xmpp_struct *xmppdat, TiXmlElement *message)
{
	const char *id;
	const char *xmlns;
    TiXmlElement *payload;
    const char *type = message->Attribute("type");
    assert(type != NULL);
    switch (a2iqtype(type)) {
	case IQ_SET:
	case IQ_GET:
		printf("iq service: %s\n", type);
		payload = message->FirstChildElement();
		if (payload == NULL) {
			message->Print(stdout, -1);
			break;
		}
		xmlns = payload->Attribute("xmlns");
		if (xmlns == NULL) {
			message->Print(stdout, -1);
			break;
		}
		printf("type: %s, xmlns: %s\n", type, xmlns);
		do_iq_service(bio, xmppdat, message);
		break;
	case IQ_ERROR:
	case IQ_RESULT:
		id = message->Attribute("id");
		assert(id != NULL);
		if (g_iq_infos.find(id) != g_iq_infos.end()) {
			*g_iq_infos[id].hPacket = *message;
			*g_iq_infos[id].hResult = 0;
			/* SetEvent(g_iq_infos[id].hEvent); */
		} else { 
			printf("incoming iq: %s\n", type);
			message->Print(stdout, -1);
		}
		break;
	default:
		assert(0);
		break;
    }
    return 0;
}

static int xmpp_stage(struct xmpp_struct *xmppdat, const char *service)
{
	int len;
	int sent;
	char buf[512];
	char proxy_server[] = "192.168.42.129:1800";
	/* char jabber_server[] = "alt1.xmpp.l.google.com:5222"; */
	char jabber_server[] = "jabbernet.dk:5222";

    BIO *bio = BIO_new_connect(proxy_server);
    if (bio == NULL) {
		fprintf(stderr, "BIO_new_connect failed!\n");
		return 0;
    }

    if (BIO_do_connect(bio) <= 0) {
		fprintf(stderr, "BIO_do_connect failed!\n");
		BIO_free_all(bio);
		return 0;
    }

	len = sprintf(buf, "CONNECT %s HTTP/1.0\r\n\r\n", jabber_server);
	fprintf(stderr, "[PROXY-TX] %s\n", buf);
	sent = BIO_write(bio, buf, len);
	assert(sent == len);

	proxy_read_handshake(bio, xmppdat);

    assert(xmppdat != NULL);
    xmppdat->available = 0;
	memset(&xmppdat->parser, 0, sizeof(xmppdat->parser));
    if (xmpp_tls_stage(bio, xmppdat) != 0){
		assert(0);
		return -1;
    }

	printf("LLLL\n");
    if (bio_tls_set(&bio) != 0) {
		assert(0);
		return -1;
    }

	printf("LLLLL\n");
    if (xmpp_sasl_stage(bio, xmppdat) != 0){
		assert(0);
		return -1;
    }
	printf("LKLLLL\n");
    if (xmpp_session_stage(bio, xmppdat) != 0){
		assert(0);
		return -1;
    }
#if 0
    appstr text = xmpp_roster(123);
    BIO_write(bio, text.c_str(), text.size());
#endif
    g_xmpp_bio = bio;
    printf("login finish, into message loop:!\n");
    xmpp_online(bio);
	
#if 1
    for (;;) {
       	TiXmlElement packet("");
       	if (xmpp_read_packet(bio, xmppdat, &packet) != 0) {
			break;
		}
		if (!strcmp(packet.Value(), "message")) {
			xmpp_message_stage(bio, xmppdat, &packet);
		}else if (!strcmp(packet.Value(), "presence")) {
			xmpp_presence_stage(bio, xmppdat, &packet);
		}else if (!strcmp(packet.Value(), "iq")) {
			xmpp_iq_stage(bio, xmppdat, &packet);
       	}else {
			packet.Print(stdout, -1);
		}
    }
#endif
    printf("all ok set\n");
    return 0;
}

static int xmpp_servers(const char *domain, srvlist *servers)
{
    char srvrcd[256];
    sprintf(srvrcd, "_xmpp-client._tcp.%s", domain);
    return srvlookup(srvrcd, servers);
}

static int xmpp_login(struct xmpp_struct *pSec)
{
    srvlist servers;
    int count = xmpp_servers(pSec->domain, &servers);
    printf("sevices count: %d\n", count);
    if (count == 0)
		return 0;
    const char *service = servers[--count].c_str();
    while (xmpp_stage(pSec, service) && count>0)
       	service = servers[--count].c_str();
    return 0;
}

void strset(char *buff, int ch, int val)
{
    char *p = buff;
    while (*p != 0) {
		if (*p == ch)
			*p = val;
		p++;
    }
}

static size_t xmpp_genid()
{
    static size_t __nxtid = 89;
    return __nxtid++;
}

static appstr xmpp_roster()
{
    appstr reqroster("<query xmlns='jabber:iq:roster'/>");
    return reqroster;
}

static void xmpp_regiq(size_t qid, tiny_event *event, TiXmlElement *packet, int *result)
{
    char iqbuff[256];
	
    struct IQInfo info;
    info.hResult = result;
    info.hEvent  = event;
    info.hPacket = packet;
	
    g_iq_infos[itoa(qid, iqbuff, 10)] = info;
}

static void xmpp_unregiq(size_t qid)
{
    char iqbuff[256];
    g_iq_infos.erase(itoa(qid, iqbuff, 10));
}

static void xmpp_write(const void *buff, size_t count)
{
    printf("xmpp_write: %s\n", (const char *)buff);
    size_t iocnt = BIO_write(g_xmpp_bio, buff, count);
    assert(iocnt == count);
}

int xmpp_iq_get(appstr payload, const char *target, TiXmlElement *packet)
{
    appstr iqstr;
    int result = -1;
    size_t qid = xmpp_genid();
    char buff[1024];
    if (target != NULL) {
       	sprintf(buff, "<iq id='%ld' type='get' to='%s'>", qid, target);
    } else {
       	sprintf(buff, "<iq id='%ld' type='get'>", qid);
    }
    iqstr = appstr(buff)+payload+"</iq>";
    tiny_event *event = create_tiny_event();
    xmpp_regiq(qid, event, packet, &result);
    xmpp_write(iqstr.c_str(), iqstr.size());
	wait_for_event(event, 10000);
    xmpp_unregiq(qid);
	close_event(event);
    return result;
}

int xmpp_get_roster(TiXmlElement *packet)
{
    appstr roster = xmpp_roster();
    return xmpp_iq_get(roster, NULL, packet);
}

#if 0
static DWORD CALLBACK InputThread(void *param)
{
    char buffer[1024];
    char *p = fgets(buffer, sizeof(buffer), stdin);
    while (p != NULL) {
		strset(p, '\r', 0); strset(p, '\n', 0);
		if (!strcmp(buffer, "ll")) {
			std::map<appstr, XmppPacket>::iterator iter;
			iter = g_online_users.begin();
			while (iter != g_online_users.end()) {
				iter->second.Print(stdout, -1);
				printf("\n");
				++iter;
			}
		}else if (!strcmp(buffer, "lf")) {
			std::map<appstr, XmppPacket>::iterator iter;
			iter = g_online_users.begin();
			while (iter != g_online_users.end()) {
				const char *jid = iter->second.Attribute("from");
				printf("%s\n", jid);
				++iter;
			}
		}else if (!strcmp(buffer, "ls")) {
			std::map<appstr, XmppPacket>::iterator iter;
			iter = g_online_users.begin();
			while (iter != g_online_users.end()) {
				const char *jid = iter->second.Attribute("from");
				printf("%s\n", jid);
				++iter;
			}
		}else if (!strcmp(buffer, "la")) {
			std::map<appstr, XmppPacket>::iterator iter;
			iter = g_roster_users.begin();
			while (iter != g_roster_users.end()) {
				printf("%s\n", iter->first.c_str());
				++iter;
			}
		}else if (!strncmp(buffer, "screen ", 6)) {
			char target[256]="default";
			TiXmlElement packet("");
			if (1==sscanf(buffer, "%*s %s", target)
				&& 0==xmpp_iq_get("<screen xmlns='screen-snapshot'/>", target, &packet)) {
				printf("snapshot\n");
				packet.Print(stdout, -1);
				printf("\n");
			}
		}else if (!strcmp(buffer, "maping")) {
			//stun_mapping("stun.ekiga.net");
		}else if (!strncmp(buffer, "vcard ", 6)) {
			char target[256]="default";
			TiXmlElement packet("");
			if (1==sscanf(buffer, "%*s %s", target)
				&& 0==xmpp_iq_get("<vCard xmlns='vcard-temp'/>", target, &packet)) {
				const char *text = packet.FirstChildElement("vCard")->FirstChildElement("PHOTO")->FirstChildElement("BINVAL")->GetText();
				if (text != NULL) {
					char *pbuff, buffer[163840];
					sprintf(buffer, "%s-photo.jpg", target);
					pbuff = strchr(buffer, '/');
					if (pbuff != NULL)
						strcpy(pbuff, "-photo.jpg");
					FILE *fpout = fopen(buffer, "wb");
					if (fpout != NULL) {
						int count = base64dec(&text, buffer, sizeof(buffer));
						fwrite(buffer, 1, count, fpout);
						fclose(fpout);
					}
				}
			}
		}else if (!strcmp(buffer, "online")) {
			TiXmlElement packet("");
			if (xmpp_get_roster(&packet) == 0) {
				const char *type = packet.Attribute("type");
				if (a2iqtype(type) == IQ_RESULT) {
					TiXmlHandle hPacket(&packet);
					TiXmlElement *item = hPacket.FirstChildElement("query").FirstChildElement("item").ToElement();
					while (item != NULL) {
						const char *jid = item->Attribute("jid");
						g_roster_users[jid] = *item;
						item = item->NextSiblingElement();
					}
				}
			} else {
				printf("xmpp_get_roster: failed");
			}
			xmpp_online(g_xmpp_bio);
		}
       	p = fgets(buffer, sizeof(buffer), stdin);
    }
    return 0;
}
#endif

static void * process_routine(void *param)
{
	struct xmpp_struct *pSec = (struct xmpp_struct*)param;
	xmpp_login(pSec);
	free((void*)pSec->password);
	free((void*)pSec->user);
	delete pSec;
	return 0;
}

int XmppClient(const char *jid, const char *passwd)
{
    base64init();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

	struct xmpp_struct *pSec = new xmpp_struct;

    char *bare = strdup(jid);
    char *user = bare, *host = NULL, *res = NULL;
    host = strsplit(bare, '@');
    if (host == NULL) {
		char _gmail_com[] = "gmail.com";
		host = _gmail_com;
	}
    res  = strsplit(host, '/');
    pSec->user = user;
    pSec->domain = host;
    pSec->resource = res;
    pSec->password = strdup(passwd);

	void *rval = 0;
	pthread_t wid = {0};
	pthread_create(&wid, NULL, process_routine, pSec);
	pthread_join(wid, &rval);
    return 0;
}

static std::string tmppresence;
static std::map<appstr, XmppPacket>::iterator iter;

 int xmpp_open_presence()
 {
	 iter = g_online_users.begin();
	 return 0;
 }

 const char *xmpp_read_presence()
 {
	 if (iter !=  g_online_users.end()) {
		 const char *jid = iter->second.Attribute("from");
		 ++iter;
		 return jid;
	 }
	 return NULL;
 }

 int xmpp_close_presence()
 {
	 return 0;
 }
