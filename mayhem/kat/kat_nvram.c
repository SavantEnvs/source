/* Known-answer probe for package/utils/nvram: parse, edit, commit and re-read NVRAM images. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nvram.h"

extern size_t nvram_part_size;

static int write_image(char *path, const void *buf, size_t len)
{
	const char *tmpdir = getenv("TMPDIR");
	int fd;

	snprintf(path, 4096, "%s/katnvramXXXXXX", tmpdir && *tmpdir ? tmpdir : "/tmp");
	fd = mkstemp(path);
	if (fd < 0)
		return -1;
	if (write(fd, buf, len) != (ssize_t)len) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void show(nvram_handle_t *h, const char *name)
{
	char *v = nvram_get(h, name);

	printf("%s=%s\n", name, v ? v : "(null)");
}

int main(void)
{
	char path[4096];
	uint8_t img[0x1000];
	nvram_header_t *hdr = (nvram_header_t *)img;
	nvram_handle_t *h;
	const char vars[] = "boardtype=0x0472\0boardnum=42\0et0macaddr=00:11:22:33:44:55\0";

	nvram_part_size = 0x1000;

	/* 1: empty image, set variables, commit, read back */
	memset(img, 0xff, sizeof(img));
	hdr->magic = NVRAM_MAGIC;
	hdr->len = sizeof(*hdr);
	hdr->crc_ver_init = 0;
	hdr->config_refresh = 0;
	hdr->config_ncdl = 0;
	memset(img + sizeof(*hdr), 0, 4);
	if (write_image(path, img, sizeof(img)))
		return 1;
	h = nvram_open(path, NVRAM_RW);
	if (!h) {
		printf("open1: failed\n");
		return 0;
	}
	nvram_set(h, "boardtype", "0x0472");
	nvram_set(h, "boardnum", "42");
	nvram_set(h, "boardtype", "0x04cf");
	nvram_set(h, "gone", "1");
	nvram_unset(h, "gone");
	nvram_commit(h);
	nvram_close(h);

	h = nvram_open(path, NVRAM_RO);
	if (!h) {
		printf("open1b: failed\n");
		return 0;
	}
	hdr = nvram_header(h);
	printf("hdr: magic=%08x len=%u ver=%u crc=%02x\n", hdr->magic, hdr->len,
	       (hdr->crc_ver_init >> 8) & 0xff, hdr->crc_ver_init & 0xff);
	show(h, "boardtype");
	show(h, "boardnum");
	show(h, "gone");
	show(h, "sdram_init");
	show(h, "sdram_config");
	show(h, "sdram_refresh");
	show(h, "sdram_ncdl");
	nvram_close(h);
	unlink(path);

	/* 2: image whose last variable is not terminated inside the partition */
	memset(img, 0, sizeof(img));
	hdr = (nvram_header_t *)img;
	hdr->magic = NVRAM_MAGIC;
	hdr->len = 0xffffff00;
	memcpy(img + sizeof(*hdr), vars, sizeof(vars) - 1);
	memcpy(img + sizeof(img) - 8, "tail=oops", 8);
	if (write_image(path, img, sizeof(img)))
		return 1;
	h = nvram_open(path, NVRAM_RO);
	if (!h) {
		printf("open2: failed\n");
		return 0;
	}
	show(h, "boardtype");
	show(h, "boardnum");
	show(h, "et0macaddr");
	show(h, "tail");
	nvram_close(h);
	unlink(path);

	/* 3: no magic */
	memset(img, 0, sizeof(img));
	if (write_image(path, img, sizeof(img)))
		return 1;
	h = nvram_open(path, NVRAM_RO);
	printf("nomagic: %s\n", h ? "opened" : "rejected");
	if (h)
		nvram_close(h);
	unlink(path);
	return 0;
}
