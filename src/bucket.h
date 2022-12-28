#ifndef BUCKET_H
#define BUCKET_H

typedef struct _VPNBucket {
	char *data;
	int size;
	int max;
} VPNBucket;

VPNBucket     *chipvpn_bucket_create(int max);
void          *chipvpn_bucket_get_buffer(VPNBucket *bucket);
int            chipvpn_bucket_read_available(VPNBucket *bucket);
int            chipvpn_bucket_write_available(VPNBucket *bucket);
int            chipvpn_bucket_write(VPNBucket *bucket, void *buf, int size);
int            chipvpn_bucket_read(VPNBucket *bucket, void *buf, int size);
int            chipvpn_bucket_consume(VPNBucket *bucket, int size);
void           chipvpn_bucket_free(VPNBucket *bucket);

#endif