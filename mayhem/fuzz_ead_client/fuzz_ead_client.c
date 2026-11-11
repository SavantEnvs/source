/*
 * Fuzz the reply handling of ead-client (package/network/services/ead): one UDP datagram, as the
 * emergency access daemon would send it, is fed to each stage of the client's state machine
 * (ping, username ack, prime, B value, auth done, command result). send_packet() drops datagrams
 * that do not carry the EAD magic and the type the stage waits for; the handlers see the rest.
 */
#include "ead-client.c"

static int peer = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int sv[2];
	int devnull;

	(void)argc;
	(void)argv;

	/* handle_pong() and handle_cmd_data() print to stdout */
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0)
		dup2(devnull, 1);

	/* the daemon's end of the "network" is a datagram socket pair */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
		return 0;
	s = sv[0];
	peer = sv[1];
	sockflags = fcntl(s, F_GETFL);

	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = 0xffffffff;
	remote.sin_port = htons(EAD_PORT);
	username = "mayhem";
	return 0;
}

static void queue_reply(const uint8_t *data, size_t size)
{
	char drain[2048];

	while (recv(peer, drain, sizeof(drain), MSG_DONTWAIT) >= 0)
		;
	while (recv(s, drain, sizeof(drain), MSG_DONTWAIT) >= 0)
		;
	(void)send(peer, data, size, MSG_DONTWAIT);
}

static void reset_client(void)
{
	static unsigned char key[40] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00, 0x00, 0x10, 0x00, 0xe4, 0xe4, 0xe4, 0xe4,
	};

	if (tc) {
		t_clientclose(tc);
		tc = NULL;
	}
	memset(msgbuf, 0, sizeof(msgbuf));
	msg->magic = htonl(EAD_MAGIC);
	nid = 0xffff;
	msg->nid = htons(nid);
	sid = 0;
	auth_type = EAD_AUTH_DEFAULT;
	timeout = 0;
	salt.len = 0;
	B.data = bbuf;
	B.len = 0;
	memset(saltbuf, 0, sizeof(saltbuf));
	memset(bbuf, 0, sizeof(bbuf));
	memset(pw_salt, 0, sizeof(pw_salt));
	ead_set_key(key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (peer < 0)
		return 0;

	reset_client();

	queue_reply(data, size);
	send_ping();

	queue_reply(data, size);
	msg->type = htonl(EAD_TYPE_SET_USERNAME);
	msg->len = htonl(sizeof(struct ead_msg_user));
	send_packet(EAD_TYPE_ACK_USERNAME, handle_none, 1);

	queue_reply(data, size);
	get_prime();

	queue_reply(data, size);
	msg->type = htonl(EAD_TYPE_SEND_A);
	msg->len = 0;
	send_packet(EAD_TYPE_SEND_B, handle_b, 1);

	if (!tc) {
		struct t_preconf *p = t_getpreparam(0);

		tc = t_clientopen(username, &p->modulus, &p->generator, &salt);
	}
	if (tc) {
		queue_reply(data, size);
		msg->type = htonl(EAD_TYPE_SEND_AUTH);
		msg->len = htonl(sizeof(struct ead_msg_auth));
		send_packet(EAD_TYPE_DONE_AUTH, handle_done_auth, 1);
	}

	queue_reply(data, size);
	msg->type = htonl(EAD_TYPE_SEND_CMD);
	msg->len = 0;
	send_packet(EAD_TYPE_RESULT_CMD, handle_cmd_data, 1);

	return 0;
}
