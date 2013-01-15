#ifndef _PARSER_H_
#define _PARSER_H_

#define is_tag_end(str) \
	(0 == strncmp(str, "</", 2))

struct xml_upp {
	int error;
	int last_type;
	int last_level;
};

const char *
xml_parse(struct xml_upp *up, const char *xmlstr);

const char *
tag_begin(struct xml_upp *up, const char *xmlstr);

const char *
tag_end(struct xml_upp *up, const char *xmlstr);

#endif


