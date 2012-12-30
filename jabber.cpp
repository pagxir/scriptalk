#include <wait/platform.h>

#include <wait/module.h>
#include <wait/slotwait.h>
#include <wait/callout.h>

void jabber_connect(const char *user, const char *password)
{
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

