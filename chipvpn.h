#ifndef CHIPVPN
#define CHIPVPN

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_MTU 1500

#define DIM(x) (sizeof(x)/sizeof(*(x)))

char       *read_string(FILE *file, char const *desired_name);
bool        read_bool(FILE *file, char const *desired_name);
int         read_int(FILE *file, char const *desired_name);
char       *read_file_into_buffer(char *file);
uint32_t    get_default_gateway();
int         exec_sprintf(char *format, ...);
void        warning(char *format, ...);
void        error(char *format, ...);
void        console_log(char *format, ...);
char       *chipvpn_malloc_fmt(char *format, ...);
uint16_t    chipvpn_checksum16(void *data, unsigned int bytes);
char       *chipvpn_resolve_hostname(char *ip);
void        chipvpn_generate_random(char *buf, int len);
uint32_t    chipvpn_get_time();

#ifdef __cplusplus
}
#endif

#endif