#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

struct xml_upp {
	int last_type;
};

int istext(int code)
{
	if (code == '<')
		return 0;

	if (code == '\0')
		return 0;

	return 1;
}

int isattr(int code)
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

const char *
bar_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (*str++ == ' ');
	return str - 1;
}

const char *
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

const char *
name_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (isalnum(*str++));
	return str - 1;
}

const char *
text_skip(const char *str)
{
	RETRUN_IF_NULL(str);
	while (istext(*str++));
	return str - 1;
}

const char *
tag_begin(struct xml_upp *up, const char *xmlstr)
{
	int type = 1;
	const char *str;
	RETRUN_IF_INVAL(xmlstr);
	str = bar_skip(xmlstr);

	if (*str != '<')
		return str;

	str = name_skip(++str);
	str = attr_skip(str);
	str = bar_skip(str);

	if (*str == '/') {
		type = 0;
		str++;
	}

	if (*str != '>')
		return str;

	up->last_type = type;
	return ++str;
}

const char *
tag_end(struct xml_upp *up, const char *xmlstr)
{
	const char *str;
	RETRUN_IF_INVAL(xmlstr);

	str = bar_skip(xmlstr);

	if (*str != '<')
		return str;

	if (*++str != '/')
		return str;

	str = name_skip(++str);
	str = bar_skip(str);

	if (*str != '>')
		return str;

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
		while (*str) {
			str = text_skip(str);
			if (str[0] == '<' && str[1] == '/') {
				str = tag_end(up, str);
				break;
			}
			str = xml_parse(up, str);
		}
	}

	return str;
}

int
main(int argc, char *argv[])
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

			xml_parse(&context, buf);
		}
	}
	free(buf);
	return 0;
}

