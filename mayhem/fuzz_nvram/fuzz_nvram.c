/* Fuzz the Broadcom NVRAM image parser/editor of package/utils/nvram (nvram_open, rehash, get/set/unset, commit). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nvram.h"

extern size_t nvram_part_size;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	/* nvram_open() maps min(partition size, file size & ~3) bytes of a regular file */
	nvram_part_size = 0x10000;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *tmpdir = getenv("TMPDIR");
	char path[4096];
	nvram_handle_t *h;
	nvram_tuple_t *all, *t, *next;
	size_t off = 0;
	int fd;

	snprintf(path, sizeof(path), "%s/nvramXXXXXX", tmpdir && *tmpdir ? tmpdir : "/tmp");
	fd = mkstemp(path);
	if (fd < 0)
		return 0;
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);
		if (n <= 0)
			break;
		off += n;
	}
	close(fd);

	/* nvram_open() returns NULL for an image without a valid header: not an NVRAM image */
	h = nvram_open(path, NVRAM_RO);
	unlink(path);
	if (!h)
		return -1;

	all = nvram_getall(h);
	for (t = all; t; t = next) {
		next = t->next;
		if (t->value)
			(void)strlen(nvram_safe_get(h, t->name));
		free(t);
	}

	(void)nvram_get(h, "boardtype");
	(void)nvram_get(h, "sdram_init");
	nvram_set(h, "mayhem_key", "mayhem_value");
	nvram_set(h, "boardtype", "0x0472");
	nvram_unset(h, "sdram_ncdl");
	nvram_commit(h);

	all = nvram_getall(h);
	for (t = all; t; t = next) {
		next = t->next;
		free(t);
	}
	nvram_close(h);
	return 0;
}
