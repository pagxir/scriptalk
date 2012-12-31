#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <wait/platform.h>
#include <wait/module.h>
#include <wait/slotwait.h>
#include <wait/callout.h>

class jabbber_t
{
	public:
	void set_user(const char *user);
	void set_password(const char *password);
	void start_login(void);

	private:
	char m_user[64];
	char m_password[64];

	BIO *m_io_con;
};

void jabbber_t::set_user(const char *user)
{
	strcpy(m_user, user);
}

void jabbber_t::set_password(const char *password)
{
	strcpy(m_password, password);
}

void jabbber_t::start_login(void)
{
	char host_domain[] = "talk.l.google.com:5223";

	m_io_con = BIO_new_connect(host_domain);
	if (m_io_con == NULL) {
		printf("BIO_new_connect failed!\n");
		return;
	}

	if (BIO_do_connect(m_io_con) <= 0) {
		printf("BIO_do_connect failed!\n");
		BIO_free_all(m_io_con);
		return;
	}

	this->available = 0;
	if (xmpp_tls_stage(m_io_con) != 0) {
		return;
	}

	if (bio_tls_set(m_io_con) != 0) {
		return;
	}

	if (xmpp_sasl_stage(m_io_con) != 0) {
		return;
	}

	if (xmpp_session_stage(m_io_con) != 0) {
		return;
	}

	xmpp_online(m_io_con);
}

void jabber_connect(const char *user, const char *password)
{
	jabbber_t * jxc =  new jabbber_t;
	jxc->set_user(user);
	jxc->set_password(password);
	jxc->start_login();
}

static void module_init(void)
{
	return;
}

static void module_clean(void)
{
	return;
}

struct module_stub jabber_mod = { 
	module_init, module_clean
};

