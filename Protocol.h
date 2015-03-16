// -*- c++-mode -*-
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <event2/bufferevent.h>

#include "Connection.h"
#include "ConnectionOptions.h"
#include "Operation.h"

using namespace std;

class Protocol {
public:
  Protocol(options_t _opts, server_t& _serv, bufferevent* _bev):
    opts(_opts), serv(_serv), bev(_bev), stats(_serv.conn->stats) {};
  virtual ~Protocol() {};

  virtual bool setup_connection_w() = 0;
  virtual bool setup_connection_r(evbuffer* input) = 0;
  virtual int  get_request(const char* key) = 0;
  virtual int  set_request(const char* key, const char* value, int len) = 0;
  virtual bool handle_response(evbuffer* input, Operation* op) = 0;

protected:
  options_t       opts;
  server_t&       serv;
  bufferevent*    bev;
  ConnectionStats stats;
};

class ProtocolAscii : public Protocol {
public:
  ProtocolAscii(options_t opts, server_t& serv, bufferevent* bev):
    Protocol(opts, serv, bev) { read_state = IDLE; };
  ~ProtocolAscii() {};

  virtual bool setup_connection_w() { return true; }
  virtual bool setup_connection_r(evbuffer* input) { return true; }
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input, Operation* op);

private:
  enum read_fsm {
    IDLE,
    WAITING_FOR_GET,
    WAITING_FOR_GET_DATA,
    WAITING_FOR_END,
  };

  read_fsm read_state;
  int data_length;
};

class ProtocolBinary : public Protocol {
public:
  ProtocolBinary(options_t opts, server_t& serv, bufferevent* bev):
    Protocol(opts, serv, bev) {};
  ~ProtocolBinary() {};

  virtual bool setup_connection_w();
  virtual bool setup_connection_r(evbuffer* input);
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input, Operation* op);
};

class ProtocolEtcd : public Protocol {
public:
  ProtocolEtcd(options_t opts, server_t& serv, bufferevent* bev):
    Protocol(opts, serv, bev) { read_state = IDLE; };
  virtual ~ProtocolEtcd() {};

  virtual bool setup_connection_w() { return true; }
  virtual bool setup_connection_r(evbuffer* input) { return true; }
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input, Operation* op);

protected:
  enum read_fsm {
    IDLE,
    WAITING_FOR_HTTP,
    WAITING_FOR_HTTP_BODY,
    LEADER_CHANGED,
  };

  read_fsm read_state;
  int data_length;
};

class ProtocolHttp : public Protocol {
public:
  ProtocolHttp(options_t opts, server_t& serv, bufferevent* bev):
    Protocol(opts, serv, bev) { read_state = IDLE; };
  virtual ~ProtocolHttp() {};

  virtual bool setup_connection_w() { return true; }
  virtual bool setup_connection_r(evbuffer* input) { return true; }
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input, Operation* op);

protected:
  enum read_fsm {
    IDLE,
    WAITING_FOR_HTTP,
    WAITING_FOR_HTTP_LEN,
    WAITING_FOR_SERVER_ID,
    WAITING_FOR_HTTP_BODY,
  };

  read_fsm read_state;
  int data_length;
};

#endif
