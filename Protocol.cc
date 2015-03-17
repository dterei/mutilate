#include <netinet/tcp.h>
#include <netinet/in.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "config.h"

#include "Connection.h"
#include "Protocol.h"
#include "distributions.h"
#include "Generator.h"
#include "mutilate.h"
#include "binary_protocol.h"
#include "util.h"

#define unlikely(x) __builtin_expect((x),0)

/**
 * Send an ascii get request.
 */
int ProtocolAscii::get_request(const char* key) {
  int l;
  l = evbuffer_add_printf(
    bufferevent_get_output(bev), "get %s\r\n", key);
  if (read_state == IDLE) read_state = WAITING_FOR_GET;
  return l;
}

/**
 * Send an ascii set request.
 */
int ProtocolAscii::set_request(const char* key, const char* value, int len) {
  int l;
  l = evbuffer_add_printf(bufferevent_get_output(bev),
                          "set %s 0 0 %d\r\n", key, len);
  bufferevent_write(bev, value, len);
  bufferevent_write(bev, "\r\n", 2);
  l += len + 2;
  if (read_state == IDLE) read_state = WAITING_FOR_END;
  return l;
}

/**
 * Handle an ascii response.
 */
bool ProtocolAscii::handle_response(evbuffer *input, Operation* op) {
  char *buf = NULL;
  int len;
  size_t n_read_out;

  while (1) {
    switch (read_state) {

    case WAITING_FOR_GET:
    case WAITING_FOR_END:
      buf = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF);
      if (buf == NULL) return false;

      stats.rx_bytes += n_read_out + 2;

      if (!strncmp(buf, "END", 3)) {
        if (read_state == WAITING_FOR_GET) stats.get_misses++;
        read_state = WAITING_FOR_GET;
        free(buf);
        return true;
      } else if (!strncmp(buf, "STORED", 6)) {
        read_state = WAITING_FOR_GET;
        free(buf);
        return true;
      } else if (!strncmp(buf, "VALUE", 5)) {
        sscanf(buf, "VALUE %*s %*d %d", &len);

        // FIXME: check key name to see if it corresponds to the op at
        // the head of the op queue?  This will be necessary to
        // support "gets" where there may be misses.

        data_length = len;
        read_state = WAITING_FOR_GET_DATA;
        free(buf);
      } else {
        DIE("Unknown line while expecting VALUE | STORED | END: %s\n", buf);
      }

    case WAITING_FOR_GET_DATA:
      len = evbuffer_get_length(input);
      if (len < data_length + 2) return false;
      evbuffer_drain(input, data_length + 2);
      read_state = WAITING_FOR_END;
      stats.rx_bytes += data_length + 2;
      break;

    default: printf("state: %d\n", read_state); DIE("Unimplemented!");
    }
  }

  DIE("Shouldn't ever reach here...");
}

/**
 * Perform SASL authentication if requested (write).
 */
bool ProtocolBinary::setup_connection_w() {
  if (!opts.sasl) return true;

  string user = string(opts.username);
  string pass = string(opts.password);

  binary_header_t header = {0x80, CMD_SASL, 0, 0, 0, {0}, 0, 0, 0};
  header.key_len = htons(5);
  header.body_len = htonl(6 + user.length() + 1 + pass.length());

  bufferevent_write(bev, &header, 24);
  bufferevent_write(bev, "PLAIN\0", 6);
  bufferevent_write(bev, user.c_str(), user.length() + 1);
  bufferevent_write(bev, pass.c_str(), pass.length());

  return false;
}

/**
 * Perform SASL authentication if requested (read).
 */
bool ProtocolBinary::setup_connection_r(evbuffer* input) {
  if (!opts.sasl) return true;
  Operation o;
  return handle_response(input, &o);
}

/**
 * Send a binary get request.
 */
int ProtocolBinary::get_request(const char* key) {
  uint16_t keylen = strlen(key);

  // each line is 4-bytes
  binary_header_t h = { 0x80, CMD_GET, htons(keylen),
                        0x00, 0x00, {htons(0)},
                        htonl(keylen) };

  bufferevent_write(bev, &h, 24); // size does not include extras
  bufferevent_write(bev, key, keylen);
  return 24 + keylen;
}

/**
 * Send a binary set request.
 */
int ProtocolBinary::set_request(const char* key, const char* value, int len) {
  uint16_t keylen = strlen(key);

  // each line is 4-bytes
  binary_header_t h = { 0x80, CMD_SET, htons(keylen),
                        0x08, 0x00, {htons(0)},
                        htonl(keylen + 8 + len) };

  bufferevent_write(bev, &h, 32); // With extras
  bufferevent_write(bev, key, keylen);
  bufferevent_write(bev, value, len);
  return 24 + h.body_len;
}

/**
 * Tries to consume a binary response (in its entirety) from an evbuffer.
 *
 * @param input evBuffer to read response from
 * @return  true if consumed, false if not enough data in buffer.
 */
bool ProtocolBinary::handle_response(evbuffer *input, Operation* op) {
  // Read the first 24 bytes as a header
  int length = evbuffer_get_length(input);
  if (length < 24) return false;
  binary_header_t* h =
    reinterpret_cast<binary_header_t*>(evbuffer_pullup(input, 24));
  assert(h);

  // Not whole response
  int targetLen = 24 + ntohl(h->body_len);
  if (length < targetLen) return false;

  // If something other than success, count it as a miss
  if (h->opcode == CMD_GET && h->status) {
      stats.get_misses++;
  }

  if (unlikely(h->opcode == CMD_SASL)) {
    if (h->status == RESP_OK) {
      V("SASL authentication succeeded");
    } else {
      DIE("SASL authentication failed");
    }
  }

  evbuffer_drain(input, targetLen);
  stats.rx_bytes += targetLen;
  return true;
}

/* Etcd get request */
static const char* get_req = "GET /v2/keys/test/%s HTTP/1.1\r\n\r\n";

/* Etcd (linearizable) get request */
static const char* get_req_linear = "GET /v2/keys/test/%s?quorum=true HTTP/1.1\r\n\r\n";

/* Perform a get request against etcd */
int ProtocolEtcd::get_request(const char* key) {
  int l;
  const char *req = get_req;
  if (opts.linear) {
    req = get_req_linear;
  }
  l = evbuffer_add_printf(bufferevent_get_output(bev), req, key);
  if (read_state == IDLE) read_state = WAITING_FOR_HTTP;
  return l;
}

/* Perform a set request against etcd */
int ProtocolEtcd::set_request(const char* key, const char* value, int len) {
  int l;
  l = evbuffer_add_printf(
    bufferevent_get_output(bev),
    "POST /v2/keys/test/%s HTTP/1.1\r\nContent-Length: %d\r\n",
    key, len + 6);
  bufferevent_write(
    bev, "Content-Type: application/x-www-form-urlencoded\r\n\r\nvalue=", 57);
  bufferevent_write(bev, value, len);
  l += len + 57;
  if (read_state == IDLE) read_state = WAITING_FOR_HTTP;
  return l;
}

/* Handle a response from etcd */
bool ProtocolEtcd::handle_response(evbuffer* input, Operation* op) {
  char *buf = NULL;
  struct evbuffer_ptr ptr;
  size_t n_read_out;
  int new_leader = 0;
  bool leader_changed;

  while (1) {
    leader_changed = false;

    switch (read_state) {

    case WAITING_FOR_HTTP:
      buf = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF);
      if (buf == NULL) return false;

      stats.rx_bytes += n_read_out + 2;

      if (!strcmp(buf, "HTTP/1.1 404 Not Found")) {
        stats.get_misses++;
      } else if (!strcmp(buf, "HTTP/1.1 200 OK")) {
        // nothing...
      } else if (!strcmp(buf, "HTTP/1.1 201 Created")) {
        // nothing...
      } else if (!strcmp(buf, "HTTP/1.1 424 status code 424")) {
        // 404 -- where leader has moved.
        leader_changed = true;
        stats.get_misses++;
      } else if (!strcmp(buf, "HTTP/1.1 422 status code 422")) {
        // 200 -- where leader has moved.
        leader_changed = true;
      } else if (!strcmp(buf, "HTTP/1.1 423 status code 423")) {
        // 201 created -- where leader has moved.
        leader_changed = true;
      } else if (!strcmp(buf, "HTTP/1.1 500 Internal Server Error")) {
#if USE_CACHED_TIME
        struct timeval now_tv;
        event_base_gettimeofday_cached(base, &now_tv);
        op->end_time = tv_to_double(&now_tv);
#elif HAVE_CLOCK_GETTIME
        op->end_time = get_time_accurate();
#else
        op->end_time = get_time();
#endif
        printf("Internal Server Error! (Op time: %fus)\n", op->time() / 1000);
        printf("Server: %d, Leader: %d\n", serv.id, serv.conn->get_leader());
        serv.conn->print_load_state();
        DIE("Unknown HTTP response: %s\n", buf);
      } else {
        DIE("Unknown HTTP response: %s\n", buf);
      }
      free(buf);

      if (leader_changed) {
        read_state = LEADER_CHANGED;
        break;
      } else {
        read_state = WAITING_FOR_HTTP_BODY;
        // fallthrough
      }

    case WAITING_FOR_HTTP_BODY:
      ptr = evbuffer_search(input, "0\r\n\r\n", 5, NULL);
      if (ptr.pos < 0) {
        stats.rx_bytes += evbuffer_get_length(input) - 1;
        evbuffer_drain(input, evbuffer_get_length(input) - 1);
        return false;
      }
      stats.rx_bytes += ptr.pos + 5;
      evbuffer_drain(input, ptr.pos + 5);
      read_state = WAITING_FOR_HTTP;
      return true;

    case LEADER_CHANGED:
      ptr = evbuffer_search(input, "X-Raft-Leader: ", 15, NULL);
      if (ptr.pos < 0) {
        stats.rx_bytes += evbuffer_get_length(input) - 14;
        evbuffer_drain(input, evbuffer_get_length(input) - 14);
        return false;
      }
      stats.rx_bytes += ptr.pos + 15;
      evbuffer_drain(input, ptr.pos + 15);
      buf = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF);
      sscanf(buf, "%d", &new_leader);
      // only change leader if we are the leader, otherwise our info may be
      // old...
      if (serv.id == serv.conn->get_leader()) {
        printf("new leader %d\n", new_leader);
        serv.conn->set_leader(new_leader);
      }
      read_state = WAITING_FOR_HTTP_BODY;
      op->switched++;
#if USE_CACHED_TIME
      struct timeval now_tv;
      event_base_gettimeofday_cached(base, &now_tv);
      op->switch_time = tv_to_double(&now_tv);
#elif HAVE_CLOCK_GETTIME
      op->switch_time = get_time_accurate();
#else
      op->switch_time = get_time();
#endif
      break;

    default: printf("state: %d\n", read_state); DIE("Unimplemented!");
    }
  }

  DIE("Shouldn't ever reach here...");
}

/* HTTP GET Request */
static const char* http_get_req = "GET /%s HTTP/1.1\r\n\r\n";
static const char* http_set_req = "POST /%s HTTP/1.1\r\nContent-Length: %d\r\n";

/* Perform a get request against a HTTP server */
int ProtocolHttp::get_request(const char* key) {
  int l;
  l = evbuffer_add_printf(bufferevent_get_output(bev), http_get_req, key);
  if (read_state == IDLE) read_state = WAITING_FOR_HTTP;
  return l;
}

/* Perform a set request against a HTTP server */
int ProtocolHttp::set_request(const char* key, const char* value, int len) {
  int l;
  l = evbuffer_add_printf(bufferevent_get_output(bev),
                          http_set_req, key, len + 6);
  bufferevent_write(
    bev, "Content-Type: application/x-www-form-urlencoded\r\n\r\nvalue=", 57);
  bufferevent_write(bev, value, len);
  l += len + 57;
  if (read_state == IDLE) read_state = WAITING_FOR_HTTP;
  return l;
}

/* Handle a response from a HTTP server */
bool ProtocolHttp::handle_response(evbuffer* input, Operation* op) {
  char *buf = NULL;
  char buff[2]; buff[1] = '\0';
  struct evbuffer_ptr ptr;
  size_t n_read_out = 0, server_id = 0;
  uint32_t drain;

  while (1) {
    switch (read_state) {

    case WAITING_FOR_HTTP:
      buf = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF);
      if (buf == NULL) return false;

      stats.rx_bytes += n_read_out + 2;

      if (!strncmp(buf, "HTTP/1.1 404 Not Found", n_read_out)) {
        stats.get_misses++;
      } else if (!strncmp(buf, "HTTP/1.1 200 OK", n_read_out)) {
        // nothing...
      } else {
        DIE("Unknown HTTP response: %s\n", buf);
      }
      free(buf);
      read_state = WAITING_FOR_HTTP_LEN;

    case WAITING_FOR_HTTP_LEN:
      #define LEN 15
      ptr = evbuffer_search(input, "Content-Length:", LEN, NULL);
      if (ptr.pos < 0) {
        stats.rx_bytes += evbuffer_get_length(input) - LEN + 1;
        evbuffer_drain(input, evbuffer_get_length(input) - LEN + 1);
        return false;
      }
      stats.rx_bytes += ptr.pos + LEN;
      evbuffer_drain(input, ptr.pos + LEN);
      buf = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF);
      sscanf(buf, "%hu", &op->len);
      read_state = WAITING_FOR_SERVER_ID;
      #undef LEN

    case WAITING_FOR_SERVER_ID:
      #define LEN 14
      ptr = evbuffer_search(input, "X-Server-Name:", LEN, NULL);
      if (ptr.pos < 0) {
        stats.rx_bytes += evbuffer_get_length(input) - LEN + 1;
        evbuffer_drain(input, evbuffer_get_length(input) - LEN + 1);
        return false;
      }
      stats.rx_bytes += ptr.pos + LEN + 2;
      evbuffer_drain(input, ptr.pos + LEN + 1);
      evbuffer_remove(input, buff, 1);
      sscanf(buff, "%ld", &server_id);
      op->server_id = server_id;
      read_state = WAITING_FOR_HTTP_BODY;
      #undef LEN

    case WAITING_FOR_HTTP_BODY:
      #define LEN 4
      ptr = evbuffer_search(input, "\r\n\r\n", LEN, NULL);
      if (ptr.pos < 0) {
        stats.rx_bytes += evbuffer_get_length(input) - LEN + 1;
        evbuffer_drain(input, evbuffer_get_length(input) - LEN + 1);
        return false;
      }
      drain = ptr.pos + LEN + op->len;
      if (drain > evbuffer_get_length(input)) {
        return false;
      }
      stats.rx_bytes += ptr.pos + LEN;
      evbuffer_drain(input, ptr.pos + LEN + op->len);
      read_state = WAITING_FOR_HTTP;
      #undef LEN
      return true;

    default: printf("state: %d\n", read_state); DIE("Unimplemented!");
    }
  }

  DIE("Shouldn't ever reach here...");
}
