#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <wait/platform.h>
#include <wait/module.h>
#include <wait/slotwait.h>
#include <wait/callout.h>

#include <map>
#include <vector>
#include <string>

#include "parser.h"
#include "tinyxml.h"
#include "srvlookup.h"
#include "base64.h"

#define BUFSIZE 65536

static int LOG_WAY = 0;
static const char *LOG_TAG = "UNKOWN";
enum {LOG_NONE, LOG_IN, LOG_OUT};

static void strset(char *buf, int ch, int val)
{
    char *p = buf;

    while (*p != 0) {
		if (*p == ch)
			*p = val;
		p++;
    }
}

static SSL_CTX *get_tlsctx()
{
    static SSL_CTX *_sslctx = NULL;

    if (_sslctx == NULL)
		_sslctx = SSL_CTX_new(TLSv1_client_method());

    return _sslctx;
}

static int bio_tls_set(BIO **iop)
{
    BIO *rawio = *iop;
    *iop = BIO_new_ssl(get_tlsctx(), 1);

    BIO_push(*iop, rawio);

    if (BIO_do_handshake(*iop) <= 0) {
        fprintf(stderr, "BIO_do_handshake failure\n");
        return -1;
    }

    return 0;
}

static char *strplit(char *str, char chr)
{
    char *p = NULL;

    if (str == NULL)
		return NULL;

    p = strchr(str, chr);
    if (p != NULL)
       	*p++ = 0;

    return p;
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

static void flushout(BIO *iop, const void *buf, size_t len)
{
	size_t count;

    count = BIO_write(iop, buf, len);

	if (LOG_WAY != LOG_OUT) {
		fprintf(stderr, "\n\n[%s-TX]: ", LOG_TAG);
		LOG_WAY = LOG_OUT;
	}

    fprintf(stderr, "%s", (const char *)buf);
    assert(len == count);
	return;
}

static int xmpp_online(BIO *iop)
{
    appstr presence = xmpp_presence();
    flushout(iop, presence.c_str(), presence.size());
    return 0;
}

class jabbercb {
private:
	BIO *g_xmpp_bio;
    const char *user;
    const char *domain;
    const char *resource;
    const char *password;

private:
    size_t avail;
	struct xml_upp parser;
    char buffer[BUFSIZE + 1];
	struct waitcb sout, sin;
	int proxy_seek_handshake(void);
	int proxy_read_handshake(BIO *iop);

private:
	int fillin(BIO *iop);
	appstr xmpp_sasl(void);
	appstr xmpp_bind(void);
	appstr xmpp_session(void);

private:
	int xmpp_tls_stage(BIO *bio);
	int xmpp_sasl_stage(BIO *bio);
	int xmpp_session_stage(BIO *bio);
	int xmpp_read_handshake(BIO *bio);
	int xmpp_seek_handshake(void);
	int xmpp_read_packet(BIO *bio, TiXmlElement *packet);

public:
	int run(void);
	static void tc_callback(void * up);

public:
	jabbercb(const char *user, const char *passwd);
	~jabbercb();
};

jabbercb::jabbercb(const char *jid, const char *passwd)
{
    char *bare = strdup(jid);
    char *user = bare, *host = NULL, *res = NULL;

    host = strplit(bare, '@');
    if (host == NULL) {
		char _gmail_com[] = "gmail.com";
		host = _gmail_com;
	}

    res  = strplit(host, '/');
    this->user = user;
    this->domain = host;
    this->resource = res;
    this->password = strdup(passwd);

	waitcb_init(&sout, tc_callback, this);
	waitcb_init(&sin, tc_callback, this);
	return;
}

jabbercb::~jabbercb()
{
	waitcb_clean(&sout);
	waitcb_clean(&sin);
	free((void *)password);
	free((void *)user);
}

int jabbercb::run(void)
{
	int len;
	char buf[512];

#if 1
#define JABBER_SERVER "jabbernet.dk:5222"
#else
#define JABBER_SERVER "alt1.xmpp.l.google.com:5222"
#endif

#ifdef _USE_PROXY_
	char target_server[] = "192.168.42.129:1800";
#else
	char target_server[] = JABBER_SERVER;
#endif

	BIO *bio = BIO_new_connect(target_server);
	if (bio == NULL) {
		fprintf(stderr, "BIO_new_connect failed!\n");
		return 0;
	}

	if (BIO_do_connect(bio) <= 0) {
		fprintf(stderr, "BIO_do_connect failed!\n");
		BIO_free_all(bio);
		return 0;
	}

#ifdef _USE_PROXY_
	LOG_TAG = "PROXY";
	len = sprintf(buf, "CONNECT %s HTTP/1.0\r\n\r\n", JABBER_SERVER);
	flushout(bio, buf, len);
	proxy_read_handshake(bio);
#endif

	LOG_TAG = "TRACE";
	this->avail = 0;
	memset(&parser, 0, sizeof(parser));
	if (xmpp_tls_stage(bio) != 0){
		assert(0);
		return 0;
	}

	if (bio_tls_set(&bio) != 0) {
		assert(0);
		return 0;
	}

	if (xmpp_sasl_stage(bio) != 0){
		assert(0);
		return 0;
	}

	if (xmpp_session_stage(bio) != 0){
		assert(0);
		return 0;
	}
#if 0
	appstr text = xmpp_roster(123);
	BIO_write(bio, text.c_str(), text.size());
#endif
	g_xmpp_bio = bio;
	printf("[I]: login finish, into message loop:!\n");
	xmpp_online(bio);

	for (;;) {
		TiXmlElement packet("");
		if (xmpp_read_packet(bio, &packet) != 0) {
			break;
		}
#if 0
		if (!strcmp(packet.Value(), "message")) {
			xmpp_message_stage(bio, &packet);
		}else if (!strcmp(packet.Value(), "presence")) {
			xmpp_presence_stage(bio, &packet);
		}else if (!strcmp(packet.Value(), "iq")) {
			xmpp_iq_stage(bio, &packet);
		}else {
			packet.Print(stdout, -1);
		}
#endif
	}

	printf("[I]: all ok set\n");
	return 0;
}

void
jabbercb::tc_callback(void * up)
{
	jabbercb * cbp;

	cbp = (jabbercb *)up;
	if (cbp->run() == 0) {
		delete cbp;
		return;
	}

	return;
}

int jabbercb::fillin(BIO *iop)
{
	int len;
	char *buf = this->buffer;
	size_t avail = this->avail;

	assert(BUFSIZE > avail);

	len = BIO_read(iop, buf + avail, BUFSIZE - avail);
	if (len == 0) {
		fprintf(stderr, "BIO_read error\n");
		exit(-2);
		return -1;
	}

	if (len == -1) {
		fprintf(stderr, "BIO_read failure\n");
		return -1;
	}

	buf[avail + len] = 0;
	this->avail = (avail + len);

	if (LOG_WAY != LOG_IN) {
		fprintf(stderr, "\n\n[%s-RX]: ", LOG_TAG);
		LOG_WAY = LOG_IN;
	}

	fwrite(buf + avail, len, 1, stderr);
	return 0;
}

int jabbercb::xmpp_seek_handshake(void)
{
    char *p = buffer;
    char *p_end = &p[avail];

	*p_end = 0;
	parser.error = 0;

	p = (char *)dec_parse(&parser, p);
	if (parser.error != 0) {
		return -1;
	}

	p = (char *)tag_begin(&parser, p);

	if (parser.error == 0) {
		this->avail = p_end - p;
		memmove(buffer, p, p_end - p + 1);
		return 0;
	}

    return -1;
}

int jabbercb::proxy_seek_handshake(void)
{
	char *s;
    char *p = buffer;

	s = strstr(p, "\r\n\r\n");
	if (s != NULL) {
		s += 4;
		this->avail = (s - p);
		memmove(buffer, s, s - p + 1);
		return 0;
	}

    return -1;
}

int jabbercb::proxy_read_handshake(BIO *bio)
{
	LOG_TAG = "PROXY";

    do {
		if (fillin(bio) != 0)
			return -1;
    } while (proxy_seek_handshake());

    return 0;
}

int jabbercb::xmpp_read_handshake(BIO *bio)
{
	LOG_TAG = "TRACE";

    do {
		if (fillin(bio) != 0)
			return -1;
    } while (xmpp_seek_handshake());

    return 0;
}

int jabbercb::xmpp_read_packet(BIO *bio, TiXmlElement *packet)
{
    int count = 0;
    const char *p = NULL;
    char *buf = this->buffer;
	
    TiXmlElement xmlparser("");
	parser.error = 0;
	parser.last_type = 0;
	parser.last_level = 0;
	buf[avail] = 0;
	p = xml_parse(&parser, buf);

	if (parser.error == 0 &&
			parser.last_type != 0 &&
			parser.last_level == 0) {
		xmlparser.Parse(buf, NULL, TIXML_ENCODING_UTF8);
		*packet = xmlparser;

		assert (avail <= BUFSIZE);
		avail -= (p - buf);
		memmove(buf, p, avail + 1);
		buf[avail] = 0;
		LOG_WAY = LOG_NONE;
		return 0;
	}

	for ( ; ; ) {
		TiXmlElement xmlparser("");

		fillin(bio);
		parser.error = 0;
		parser.last_type = 0;
		parser.last_level = 0;
		buf[avail] = 0;
		p = xml_parse(&parser, buf);

		if (parser.error == 0 &&
				parser.last_type != 0 &&
				parser.last_level == 0) {
			xmlparser.Parse(buf, NULL, TIXML_ENCODING_UTF8);
			*packet = xmlparser;

			assert (avail <= BUFSIZE);
			avail -= (p - buf);
			memmove(buf, p, avail + 1);
			buf[avail] = 0;
			LOG_WAY = LOG_NONE;
			return 0;
		}
	}

	return -1;
}

int jabbercb::xmpp_tls_stage(BIO *bio)
{
    appstr handshake = xmpp_handshake(domain);
	flushout(bio, handshake.c_str(), handshake.size());
	
    this->avail = 0;
    if (xmpp_read_handshake(bio) != 0) {
		assert(0);
		return -1;
    }
	
    TiXmlElement packet("");
    if (xmpp_read_packet(bio, &packet) != 0) {
		assert(0);
		return -1;
    }
	
    appstr starttls = xmpp_starttls();
	flushout(bio, starttls.c_str(), starttls.size());
	
    TiXmlElement proceed("");
    if (xmpp_read_packet(bio, &proceed) != 0) {
		assert(0);
		return -1;
    }

    return 0;
}

appstr jabbercb::xmpp_sasl(void)
{
	int count;
    appstr sasl;
    char buf[1024];

    count = sprintf(buf, "@%s@%s", user, password);
    buf[strlen(user) + 1] = buf[0] = 0;
	
    sasl = "<auth mechanism='PLAIN' xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>";
    sasl += bin2B64str(buf, count);
    sasl += "</auth>'";
    return sasl;
}

appstr jabbercb::xmpp_bind(void)
{
    appstr t("<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>");

    if (resource && resource[0]) {
		t =  "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>";
		t += this->resource;
		t += "</resource></bind>";
    }

    appstr bind = "<iq id='bind0' type='set'>";
    bind += t;
    bind += "</iq>";
    return bind;
}

appstr jabbercb::xmpp_session(void)
{
    appstr session;
    session = "<iq id='1' type='set'>";
    session += "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>";
    session += "</iq>";
    return session;
}

int jabbercb::xmpp_sasl_stage(BIO *bio)
{
    appstr handshake = xmpp_handshake(domain);
	flushout(bio, handshake.c_str(), handshake.size());
	
    this->avail = 0;
    if (xmpp_read_handshake(bio) != 0) {
		assert(0);
		return -1;
    }
	
    TiXmlElement packet("");
    if (xmpp_read_packet(bio, &packet) != 0) {
		assert(0);
		return -1;
    }
	
    appstr sasl = xmpp_sasl();
	flushout(bio, sasl.c_str(), sasl.size());

    TiXmlElement authresult("");
    if (xmpp_read_packet(bio, &authresult) != 0) {
		assert(0);
		return -1;
    }

    if (strcmp(authresult.Value(), "success")) {
		assert(0);
		return -1;
    }

    return 0;
}

int jabbercb::xmpp_session_stage(BIO *bio)
{
    appstr handshake = xmpp_handshake(domain);
	flushout(bio, handshake.c_str(), handshake.size());

    if (xmpp_read_handshake(bio) != 0) {
		assert(0);
		return -1;
    }
	
    TiXmlElement packet("");
    if (xmpp_read_packet(bio, &packet) != 0) {
		assert(0);
		return -1;
    }
	
    appstr bind = xmpp_bind();
    flushout(bio, bind.c_str(), bind.size());
	
    TiXmlElement bindresult("");
    if (xmpp_read_packet(bio, &bindresult) != 0) {
		assert(0);
		return -1;
    }
    const char *jidText = NULL;
    TiXmlHandle hBindResult(&bindresult);
    TiXmlElement *jidNode = hBindResult.FirstChildElement("bind").
		FirstChildElement("jid").ToElement();

    if (jidNode != NULL && (jidText = jidNode->GetText())) {
		printf("\n\n[I]: local client jid: %s\n", jidText);
		LOG_WAY = LOG_NONE;
    }
	
    appstr session = xmpp_session();
    flushout(bio, session.c_str(), session.size());
	
    TiXmlElement sessresult("");
    if (xmpp_read_packet(bio, &sessresult) != 0) {
		assert(0);
		return -1;
    }
    return 0;
}

int XmppClient(const char *jid, const char *passwd)
{
	struct jabbercb *up;
	
	up = new jabbercb(jid, passwd);
	if (up == NULL)
		return -1;

	jabbercb::tc_callback(up);
    return 0;
}

static void module_init(void)
{
    base64init();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

	fprintf(stderr, "[II] OpenSSL_add_all_algorithms\n");
	return;
}

static void module_clean(void)
{
	return;
}

struct module_stub jabber_mod = { 
	module_init, module_clean
};

