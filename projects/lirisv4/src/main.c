/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
LOG_MODULE_REGISTER(ipsp);

/* Preventing log module registration in net_core.h */
#define NET_LOG_ENABLED	0

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/net_ip.h>
#include <net/udp.h>
#include <net/socket.h>

#include <drivers/gpio.h>


#include <net/coap.h>
#include <net/coap_link_format.h>

/* Define my IP address where to expect messages */
#define MY_IP6ADDR { { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, \
			 0, 0, 0, 0, 0, 0, 0, 0x1 } } }

#define MY_COAP_PORT 5683
#define MAX_COAP_MSG_LEN 256
#define NUM_OBSERVERS 3
#define NUM_PENDINGS 10
#define BLOCK_WISE_TRANSFER_SIZE_GET 4096

struct gpio_dt_spec led = GPIO_DT_SPEC_GET_OR(DT_ALIAS(led0), gpios, {0});

static struct in6_addr in6addr_my = MY_IP6ADDR;
static int sock;

static struct coap_observer observers[NUM_OBSERVERS];

static struct coap_pending pendings[NUM_PENDINGS];

static int send_coap_reply(struct coap_packet *cpkt,
			   const struct sockaddr *addr,
			   socklen_t addr_len)
{
	int r;

	LOG_HEXDUMP_INF(cpkt->data, cpkt->offset, "Response");

	r = sendto(sock, cpkt->data, cpkt->offset, 0, addr, addr_len);
	if (r < 0) {
		LOG_ERR("Failed to send %d", errno);
		r = -errno;
	}

	return r;
}

static int well_known_core_get(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t *data;
	int r;

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_well_known_core_get(resource, request, &response,
				     data, MAX_COAP_MSG_LEN);
	if (r < 0) {
		goto end;
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}

static int led0_get(struct coap_resource *resource,
		     struct coap_packet *request,
		     struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	struct coap_packet response;
	uint8_t payload[40];
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t *data;
	uint16_t id;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	uint32_t led0_value;
	int i, r;

	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	r = coap_find_options(request, COAP_OPTION_URI_QUERY, options, 4);
	if (r < 0) {
		return -EINVAL;
	}

	LOG_INF("*******");
	LOG_INF("type: %u code %u id %u", type, code, id);
	LOG_INF("num queries: %d", r);

	for (i = 0; i < r; i++) {
		char str[16];

		if (options[i].len + 1 > sizeof(str)) {
			LOG_INF("Unexpected length of query: "
				"%d (expected %zu)",
				options[i].len, sizeof(str));
			break;
		}

		memcpy(str, options[i].value, options[i].len);
		str[options[i].len] = '\0';

		LOG_INF("query[%d]: %s", i + 1, str);
	}

	LOG_INF("*******");

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&response, data, MAX_COAP_MSG_LEN,
			     COAP_VERSION_1, COAP_TYPE_ACK, tkl, token,
			     COAP_RESPONSE_CODE_CONTENT, id);
	if (r < 0) {
		goto end;
	}

	r = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
				   COAP_CONTENT_FORMAT_TEXT_PLAIN);
	if (r < 0) {
		goto end;
	}

	r = coap_packet_append_payload_marker(&response);
	if (r < 0) {
		goto end;
	}
	gpio_port_get(led.port, &led0_value);
	/* The response that coap-client expects */
	r = snprintk((char *) payload, sizeof(payload),
		     "Led0 Value: %u\n", led0_value);
	if (r < 0) {
		goto end;
	}

	r = coap_packet_append_payload(&response, (uint8_t *)payload,
				       strlen(payload));
	if (r < 0) {
		goto end;
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}

static int led0_put(struct coap_resource *resource,
		    struct coap_packet *request,
		    struct sockaddr *addr, socklen_t addr_len)
{
	const char* led_on = "ON";
	const char* led_off = "OFF";
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	const uint8_t *payload;
	uint8_t *data;
	uint16_t payload_len;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	uint16_t id;
	int8_t led_value = -1;
	int r;

	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	LOG_INF("*******");
	LOG_INF("type: %u code %u id %u", type, code, id);
	LOG_INF("*******");

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload) {
		LOG_HEXDUMP_INF(payload, payload_len,"PUT Payload: ");
	}

	if(0 == strncmp((const char*)payload, led_on, strlen(led_on))) {
		LOG_INF("Switching on led0");
		led_value = 1;
	} else if(0 == strncmp((const char*)payload, led_off, strlen(led_off))) {
		LOG_INF("Switching off led0");
		led_value = 0;
	} else {
		LOG_ERR("Unsupported value for led0");
	}

	if ((led.port != NULL) && (led_value > -1)) {
		LOG_INF("Changing led0 vale to %u", (unsigned int) led_value);
		gpio_pin_set(led.port, led.pin, led_value);
	}
	
	if (type == COAP_TYPE_CON) {
		type = COAP_TYPE_ACK;
	} else {
		type = COAP_TYPE_NON_CON;
	}

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&response, data, MAX_COAP_MSG_LEN,
			     COAP_VERSION_1, type, tkl, token,
			     COAP_RESPONSE_CODE_CHANGED, id);
	if (r < 0) {
		goto end;
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}

static int large_get(struct coap_resource *resource,
		     struct coap_packet *request,
		     struct sockaddr *addr, socklen_t addr_len)

{
	static struct coap_block_context ctx;
	struct coap_packet response;
	uint8_t payload[64];
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t *data;
	uint16_t size;
	uint16_t id;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	int r;

	if (ctx.total_size == 0) {
		coap_block_transfer_init(&ctx, COAP_BLOCK_64,
					 BLOCK_WISE_TRANSFER_SIZE_GET);
	}

	r = coap_update_from_block(request, &ctx);
	if (r < 0) {
		return -EINVAL;
	}

	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	LOG_INF("*******");
	LOG_INF("type: %u code %u id %u", type, code, id);
	LOG_INF("*******");

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&response, data, MAX_COAP_MSG_LEN,
			     COAP_VERSION_1, COAP_TYPE_ACK, tkl, token,
			     COAP_RESPONSE_CODE_CONTENT, id);
	if (r < 0) {
		return -EINVAL;
	}

	r = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
				   COAP_CONTENT_FORMAT_TEXT_PLAIN);
	if (r < 0) {
		goto end;
	}

	r = coap_append_block2_option(&response, &ctx);
	if (r < 0) {
		goto end;
	}

	r = coap_packet_append_payload_marker(&response);
	if (r < 0) {
		goto end;
	}

	size = MIN(coap_block_size_to_bytes(ctx.block_size),
		   ctx.total_size - ctx.current);

	memset(payload, 'A', MIN(size, sizeof(payload)));

	r = coap_packet_append_payload(&response, (uint8_t *)payload, size);
	if (r < 0) {
		goto end;
	}

	r = coap_next_block(&response, &ctx);
	if (!r) {
		/* Will return 0 when it's the last block. */
		memset(&ctx, 0, sizeof(ctx));
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}


static const char * const led0_path[] = { "led0", NULL };
static const char * const large_path[] = { "large", NULL };

static struct coap_resource resources[] = {
	{ .get = well_known_core_get,
	  .path = COAP_WELL_KNOWN_CORE_PATH,
	},
	{ .get = led0_get,
	  .put = led0_put,
	  .path = led0_path,
	},
	{ .path = large_path,
	  .get = large_get,
	},
	{ },
};

static struct coap_resource *find_resource_by_observer(
		struct coap_resource *resources, struct coap_observer *o)
{
	struct coap_resource *r;

	for (r = resources; r && r->path; r++) {
		sys_snode_t *node;

		SYS_SLIST_FOR_EACH_NODE(&r->observers, node) {
			if (&o->list == node) {
				return r;
			}
		}
	}

	return NULL;
}

static void init_app(void)
{
	LOG_INF("Run IPSP sample");

	if (net_addr_pton(AF_INET6,
			  CONFIG_NET_CONFIG_MY_IPV6_ADDR,
			  &in6addr_my) < 0) {
		LOG_ERR("Invalid IPv6 address %s",
			CONFIG_NET_CONFIG_MY_IPV6_ADDR);
	}

	do {
		struct net_if_addr *ifaddr;

		ifaddr = net_if_ipv6_addr_add(net_if_get_default(),
					      &in6addr_my, NET_ADDR_MANUAL, 0);
	} while (0);
}

static int start_coap_server(void)
{
	struct sockaddr_in6 addr6;
	int r;

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(MY_COAP_PORT);

	sock = socket(addr6.sin6_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	}

	r = bind(sock, (struct sockaddr *)&addr6, sizeof(addr6));
	if (r < 0) {
		LOG_ERR("Failed to bind UDP socket %d", errno);
		return -errno;
	}
	LOG_INF("Server started succussfully");

	return 0;
}

static void remove_observer(struct sockaddr *addr)
{
	struct coap_resource *r;
	struct coap_observer *o;

	o = coap_find_observer_by_addr(observers, NUM_OBSERVERS, addr);
	if (!o) {
		return;
	}

	r = find_resource_by_observer(resources, o);
	if (!r) {
		LOG_ERR("Observer found but Resource not found\n");
		return;
	}

	LOG_INF("Removing observer %p", o);

	coap_remove_observer(r, o);
	memset(o, 0, sizeof(struct coap_observer));
}

static void process_coap_request(uint8_t *data, uint16_t data_len,
				 struct sockaddr *client_addr,
				 socklen_t client_addr_len)
{
	struct coap_packet request;
	struct coap_pending *pending;
	struct coap_option options[16] = { 0 };
	uint8_t opt_num = 16U;
	uint8_t type;
	int r;

	r = coap_packet_parse(&request, data, data_len, options, opt_num);
	if (r < 0) {
		LOG_ERR("Invalid data received (%d)\n", r);
		return;
	}

	type = coap_header_get_type(&request);

	pending = coap_pending_received(&request, pendings, NUM_PENDINGS);
	if (!pending) {
		goto not_found;
	}

	/* Clear CoAP pending request */
	if (type == COAP_TYPE_ACK || type == COAP_TYPE_RESET) {
		k_free(pending->data);
		coap_pending_clear(pending);

		if (type == COAP_TYPE_RESET) {
			remove_observer(client_addr);
		}
	}

	return;

not_found:
	r = coap_handle_request(&request, resources, options, opt_num,
				client_addr, client_addr_len);
	if (r < 0) {
		LOG_WRN("No handler for such request (%d)\n", r);
	}
}

static int process_client_request(void)
{
	int received;
	struct sockaddr client_addr;
	socklen_t client_addr_len;
	uint8_t request[MAX_COAP_MSG_LEN];

	do {
		client_addr_len = sizeof(client_addr);
		received = recvfrom(sock, request, sizeof(request), 0,
				    &client_addr, &client_addr_len);
		if (received < 0) {
			LOG_ERR("Connection error %d", errno);
			return -errno;
		}
		process_coap_request(request, received, &client_addr,
				     client_addr_len);
	} while (true);

	return 0;
}

static void led0_init(void)
{
	int ret;
	if (led.port != NULL) {
		if (!device_is_ready(led.port)) {
			LOG_ERR("LED Device %s not ready.\n",
			       led.port->name);
			return;
		}
		ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_HIGH);
		if (ret < 0) {
			LOG_ERR("Error setting LED pin to output mode [%d]",
			       ret);
			led.port = NULL;
		}
	}
}

void main(void)
{
	/* Initialize led 0 */
	led0_init();

	if(0 != start_coap_server()) {
		LOG_ERR("Cannot get network contexts");
		return;
	}

	init_app();

	LOG_INF("Starting to wait");

	process_client_request();

	while(1) {
		k_cpu_idle();
	}
}
