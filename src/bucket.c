#include <stdlib.h>
#include <string.h>
#include "chipvpn.h"
#include "bucket.h"

VPNBucket *chipvpn_bucket_create(int max) {
	VPNBucket *bucket = malloc(sizeof(VPNBucket));
	bucket->data = malloc(sizeof(char) * 1);
	bucket->size = 0;
	bucket->max = max;
	return bucket;
}

char *chipvpn_bucket_get_buffer(VPNBucket *bucket) {
	return bucket->data;
}

int chipvpn_bucket_read_available(VPNBucket *bucket) {
	return bucket->size;
}

int chipvpn_bucket_write_available(VPNBucket *bucket) {
	return bucket->max - bucket->size;
}

int chipvpn_bucket_write(VPNBucket *bucket, void *buf, int size) {
	bucket->data = realloc(bucket->data, bucket->size + size);
	memcpy(bucket->data + bucket->size, buf, size);
	bucket->size += size;

	return size;
}

int chipvpn_bucket_read(VPNBucket *bucket, void *buf, int size) {
	size = MIN(bucket->size, size);

	memcpy(buf, bucket->data, size);
	memmove(bucket->data, bucket->data + size, bucket->size - size);
	bucket->size -= size;
	bucket->data = realloc(bucket->data, bucket->size);

	return size;
}

int chipvpn_bucket_consume(VPNBucket *bucket, int size) {
	size = MIN(bucket->size, size);

	memmove(bucket->data, bucket->data + size, bucket->size - size);
	bucket->size -= size;
	bucket->data = realloc(bucket->data, bucket->size);

	return size;
}

void chipvpn_bucket_free(VPNBucket *bucket) {
	free(bucket->data);
	free(bucket);
}