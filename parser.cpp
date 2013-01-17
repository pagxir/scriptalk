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
char_inset(int dot, const char *s)
{
	int sel;
	int neg = 1;

	if (*s++ != '[')
		return 0;

	if (*s == '^') {
		neg = 0;
		s++;
	}

	while (*s && *s != ']') {
		if (strncmp("A-Z", s, 3) == 0) {
			if (dot >= 'A' && dot <= 'Z') {
				return neg;
			}
			s += 3;
		} else if (strncmp("a-z", s, 3) == 0) {
			if (dot >= 'a' && dot <= 'z') {
				return neg;
			}
			s += 3;
		} else if (strncmp("0-9", s, 3) == 0) {
			if (dot >= '0' && dot <= '9') {
				return neg;
			}
			s += 3;
		} else {
			if (*s == dot) {
				return neg;
			}
			s++;
		}
	}

	return !neg;
}

static const char *
bar_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (char_inset(*str++, "[\r\n ]"));
	return str - 1;
}

static const char *
attr_skip(const char *str)
{
	RETRUN_IF_NULL(str);

	do {
		int bar;
		while (char_inset(*str++, "[A-Za-z0-9:= ]"));

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
	while (char_inset(*str++, "[A-Za-z0-9:]"));
	return str - 1;
}

static const char *
text_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (char_inset(*str++, "[^<]"));
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
		type = 2;
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
	xmlstr = bar_skip(xmlstr);
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

			printf("[XML]: %s", doc_parse(&context, buf));
			printf("error %d, type %d\n", context.error, context.last_type);
		}
	}
	free(buf);
	return 0;
}
#endif

