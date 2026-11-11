/* Known-answer probe for the ead crypto helpers: MD5 crypt and the AES/SHA-1 message protection. */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ead.h"
#include "ead-crypt.h"

#include "pw_encrypt_md5.c"

static void hex(const unsigned char *p, int n)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

int main(void)
{
	static unsigned char key[40] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00, 0x00, 0x10, 0x00, 0xe4, 0xe4, 0xe4, 0xe4,
	};
	char out[MD5_OUT_BUFSIZE];
	char buf[1500];
	struct ead_msg *msg = (struct ead_msg *)buf;
	struct ead_msg_encrypted *enc = EAD_DATA(msg, enc);
	struct ead_msg_cmd *cmd = EAD_ENC_DATA(msg, cmd);
	const char command[] = "echo hi";
	int len, enclen;

	printf("md5crypt: %s\n", md5_crypt(out, (const unsigned char *)"password", (const unsigned char *)"$1$salt$"));

	memset(buf, 0, sizeof(buf));
	msg->magic = htonl(EAD_MAGIC);
	ead_set_key(key);
	msg->type = htonl(EAD_TYPE_SEND_CMD);
	cmd->type = htons(EAD_CMD_NORMAL);
	cmd->timeout = htons(10);
	strcpy((char *)cmd->data, command);
	ead_encrypt_message(msg, sizeof(struct ead_msg_cmd) + sizeof(command));
	len = ntohl(msg->len);
	printf("enclen: %d\n", len);
	hex((unsigned char *)enc, len);

	ead_set_key(key);
	enclen = ead_decrypt_message(msg);
	printf("declen: %d\n", enclen);
	printf("dectext: %s\n", (const char *)cmd->data);

	msg->len = htonl(len - 16);
	ead_set_key(key);
	printf("badlen: %d\n", ead_decrypt_message(msg));
	return 0;
}
