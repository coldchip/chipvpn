#include "chipvpn.h"

char *read_file_into_buffer(char *file) {
	FILE *infp = fopen(file, "rb");
    if (!infp) {
    	return NULL;
    }
    fseek(infp, 0, SEEK_END);
	long fsize = ftell(infp);
	char *p = malloc(fsize + 1);
	fseek(infp, 0, SEEK_SET);

	if(fread((char*)p, 1, fsize, infp)) {}

	fclose(infp);
	*(p + fsize) = '\0';

	return p;
}

char *read_string(FILE *file, char const *desired_name) { 
    char name[1024];
    char val[1024];

	memset(name, 0, sizeof(name));
	memset(val , 0, sizeof(val ));
    int rewind = ftell(file);
    while (fscanf(file, "%1023[^=]=%1023[^\n]%*c", name, val) == 2) {
        if (0 == strcmp(name, desired_name)) {
            fseek(file, rewind, SEEK_SET);
            return strdup(val);
        }
    }
    fseek(file, rewind, SEEK_SET);
    return NULL;
}

bool read_bool(FILE *file, char const *desired_name) { 
    char name[1024];
    char val[1024];

	memset(name, 0, sizeof(name));
	memset(val , 0, sizeof(val ));
    int rewind = ftell(file);
    while (fscanf(file, "%1023[^=]=%1023[^\n]%*c", name, val) == 2) {
        if (0 == strcmp(name, desired_name)) {
            if (0 == strcmp(val, "true")) {
                fseek(file, rewind, SEEK_SET);
            	return true;
        	}
        }
    }
    fseek(file, rewind, SEEK_SET);
    return false;
}

int read_int(FILE *file, char const *desired_name) { 
    char name[1024];
    char val[1024];

	memset(name, 0, sizeof(name));
	memset(val , 0, sizeof(val ));
    int rewind = ftell(file);
    while (fscanf(file, "%1023[^=]=%1023[^\n]%*c", name, val) == 2) {
        if (0 == strcmp(name, desired_name)) {
            fseek(file, rewind, SEEK_SET);
            return atoi(val);
        }
    }
    fseek(file, rewind, SEEK_SET);
    return 0;
}

uint32_t get_default_gateway() {
    char ip_addr[16];
    char cmd[] = "ip route show default | awk '/default/ {print $3}' |  tr -cd '[a-zA-Z0-9]._-'";
    FILE* fp = popen(cmd, "r");

    if(fgets(ip_addr, 16, fp) != NULL){
        //printf("%s\n", line);
    }
    pclose(fp);
    ip_addr[15] = '\0';
    return inet_addr(ip_addr);
}

int exec_sprintf(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];

	vsnprintf(fmt, sizeof(fmt), format, args);

	int res = system(fmt);
    
    va_end(args);

    return res;
}

void console_log(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;32m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
    
    va_end(args);
}

void warning(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;31m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
    
    va_end(args);
}

void error(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;31m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
    
    va_end(args);
	exit(1);
}

char *format_size(uint64_t size) {
    const char     *sizes[]   = { "EB", "PB", "TB", "GB", "MB", "KB", "B" };
    const uint64_t  exbibytes = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;

    char     *result = (char *) malloc(sizeof(char) * 20);
    uint64_t  multiplier = exbibytes;
    int i;

    for (i = 0; i < DIM(sizes); i++, multiplier /= 1024)
    {   
        if (size < multiplier)
            continue;
        if (size % multiplier == 0)
            sprintf(result, "%llu %s", (long long)(size / multiplier), sizes[i]);
        else
            sprintf(result, "%.1f %s", (float) size / multiplier, sizes[i]);
        return result;
    }
    strcpy(result, "0");
    return result;
}

char *chipvpn_malloc_fmt(char *format, ...) {
    va_list args;
    va_start(args, format);
    int len = vsnprintf(NULL, 0, format, args);
    va_end(args);
    
    va_start(args, format);
    char *result = malloc((len * sizeof(char)) + 1);
    vsnprintf(result, len + 1, format, args);
    va_end(args);

    return result;
}