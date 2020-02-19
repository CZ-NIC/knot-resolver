#include <stdlib.h>
#include <string.h>
#include "string_helper.h"

/// Source: https://stackoverflow.com/questions/47116974/remove-a-substring-from-a-string-in-c
char *remove_substr(char *str, const char *substr) {
	char *p, *q, *r;
	if ((q = r = strstr(str, substr)) != NULL) {
		size_t len = strlen(substr);
		while ((r = strstr(p = r + len, substr)) != NULL) {
			while (p < r)
				*q++ = *p++;
		}
		while ((*q++ = *p++) != '\0')
			continue;
	}
	return str;
}

/// Source: https://stackoverflow.com/questions/40195731/how-to-concatenate-two-char-arrays-in-c
char *concat(const char *a, const char *b){
	int lena = strlen(a);
	int lenb = strlen(b);
	char *con = malloc(lena+lenb+1);
	// copy & concat (including string termination)
	memcpy(con,a,lena);
	memcpy(con+lena,b,lenb+1);
	return con;
}

char *replace_char(char *str, const char subchar, const char repchar) {
	for(int i = 0; str[i] != '\0'; i++)
		if(str[i] == subchar) str[i] = repchar;
	return str;
}

int starts_with(char *str, const char *start_str){
	int rc = strncmp(str, start_str, strlen(start_str));
	return rc;
}
