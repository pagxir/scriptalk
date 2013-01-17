#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"

#define RETRUN_IF_INVAL(p)	\
	do {					\
		if (p == NULL		\
			||	*p == '\0')	\
			return p;		\
	} while ( 0 )

#define RETRUN_IF_NULL(p)	\
	do {					\
		if (p == NULL)		\
			return p;		\
	} while ( 0 )

static int
istext(int code)
{
	if (code == '<')
		return 0;

	if (code == '\0')
		return 0;

	return 1;
}

static int
isattr(int code)
{
	switch (code) {
		case ':':
		case '=':
		case ' ':
			break;

		default:
			return isalnum(code);
	}

	return 1;
}

static const char *
bar_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (*str++ == ' ');
	return str - 1;
}

static const char *
attr_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	do {
		int bar;
		while (isattr(*str++));

		bar = str[-1];
		if (bar == '\"' || bar == '\'') {
			while (*str != bar && *str != 0) str++;
			str++;
		} else {
			break;
		}

	} while (1);

	return str - 1;
}

static const char *
name_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (isalnum(*str++));
	return str - 1;
}

static const char *
text_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (istext(*str++));
	return str - 1;
}

const char *
dec_parse(struct xml_upp *up, const char *xmlstr)
{
	const char *str;

	str = xmlstr;
	if (strncmp(str, "<?", 2))
		return xmlstr;

	str = name_skip(str + 2);
	str = attr_skip(str);
	str = bar_skip(str);

	if (strncmp(str, "?>", 2)) {
		up->error = 1;
		return str;
	}

	return (str + 2);
}

const char *
tag_begin(struct xml_upp *up, const char *xmlstr)
{
	int type = 1;
	const char *str;
	RETRUN_IF_INVAL(xmlstr);
	str = bar_skip(xmlstr);

	if (*str != '<') {
		up->error = 1;
		return str;
	}

	str = name_skip(++str);
	str = attr_skip(str);
	str = bar_skip(str);

	if (*str == '/') {
		type = 0;
		str++;
	}

	if (*str != '>') {
		up->error = 1;
		return str;
	}

	up->last_type = type;
	return ++str;
}

const char *
tag_end(struct xml_upp *up, const char *xmlstr)
{
	const char *str;
	RETRUN_IF_INVAL(xmlstr);

	str = bar_skip(xmlstr);

	if (*str != '<') {
		up->error = 1;
		return str;
	}

	if (*++str != '/') {
		up->error = 1;
		return str;
	}

	str = name_skip(++str);
	str = bar_skip(str);

	if (*str != '>') {
		up->error = 1;
		return str;
	}

	return ++str;
}

const char *
xml_parse(struct xml_upp *up, const char *xmlstr)
{
	const char *str;
	RETRUN_IF_INVAL(xmlstr);

	up->last_type = 0;

	str = bar_skip(xmlstr);
	str = tag_begin(up, str);

	if (up->last_type == 1) {
		str = text_skip(str);

		up->last_level++;
		while (*str && !is_tag_end(str)) {
			str = xml_parse(up, str);
			if (up->error)
				return str;
			str = text_skip(str);
		}

		if (is_tag_end(str)) {
			str = tag_end(up, str);
			up->last_level--;
			up->error = 0;
		}
	}

	return str;
}

const char *
doc_parse(struct xml_upp *up, const char *xmlstr)
{
	xmlstr = dec_parse(up, xmlstr);
	if (up->error)
		return xmlstr;
	return xml_parse(up, xmlstr);
}

#ifndef _USE_LIB_
int main(int argc, char *argv[])
{
	int i;
	char *buf;
	FILE *fp;

	buf = (char *)malloc(1024 * 1024);
	for (i = 1; i < argc; i++) {
		fp = fopen(argv[i], "rb");
		if (fp != NULL) {
			struct xml_upp context = {0};
			int l = fread(buf, 1, 1024 * 1024, fp);

			buf[l] = 0;
			fclose(fp);

			printf("%s", doc_parse(&context, buf));
		}
	}
	free(buf);
	return 0;
}
#endif

