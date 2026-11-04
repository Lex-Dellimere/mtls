# Non-blocking use

`MtlsConn` never touches a socket. It holds two queues: bytes that came
from the network and bytes that must go to it. Your event loop moves
bytes between those queues and the socket; mtls does the rest.

| Step | Call |
|---|---|
| What does the connection need? | `mtls_conn_wants(c)`: `MTLS_WANT_READ`, `MTLS_WANT_WRITE`, both, or 0 |
| Socket readable | `mtls_conn_in_space(c, &p)` gives room; read into it; `mtls_conn_in_commit(c, n)` |
| Socket writable | `mtls_conn_out_peek(c, &p)` gives bytes; write some; `mtls_conn_out_done(c, n)` |
| Handshake finished? | `mtls_conn_handshaking(c)` is false and `mtls_conn_error(c)` is 0 |
| Application data in | `mtls_conn_read(c, buf, cap)`: count, 0 at a clean end, `MTLS_E_WANT_IO` for "wait" |
| Application data out | `mtls_conn_write(c, p, n)`, then flush when writable |
| Close | `mtls_conn_close(c)`, flush, `mtls_conn_free(c)` |

`mtls_conn_feed(c, p, n)` and `mtls_conn_take_out(c, buf, cap)` are
copying versions of the in/out calls, handy for tests and pipes.

A connection that holds unread application data stops taking input until
you read it. That is backpressure, not an error: read, then feed again.

## With alph

alph actors own non-blocking descriptors through `alph_io_open` and get an
`ALPH_TAG_IO` message when one is ready. One TLS connection per actor:

```mettle
fn on_io(ctx: AlphCtx*, st: Conn*) {
  var p: uint8* = (uint8*)0;
  // readable: pull bytes into mtls
  var room: int64 = mtls_conn_in_space(st->tls, &p);
  var n: int64 = alph_io_read(ctx, st->h, p, room);
  if (n > 0) { mtls_conn_in_commit(st->tls, n); }
  // writable: push what mtls queued
  var k: int64 = mtls_conn_out_peek(st->tls, &p);
  if (k > 0) {
    var w: int64 = alph_io_write(ctx, st->h, p, k);
    if (w > 0) { mtls_conn_out_done(st->tls, w); }
  }
  // arm for whatever is still needed
  var ev: int64 = 0;
  var want: int32 = mtls_conn_wants(st->tls);
  if ((want & MTLS_WANT_READ) != 0) { ev = ev | ALPH_IO_IN; }
  if ((want & MTLS_WANT_WRITE) != 0) { ev = ev | ALPH_IO_OUT; }
  if (ev != 0) { alph_io_arm(ctx, st->h, ev); }
}
```

A client calls `mtls_client_start(c, host)` once before the first event;
that queues the ClientHello. A server connection waits for one.

## Blocking

`MtlsStream` (src/tls/stream.mettle) wraps the same calls over a blocking
std/socket descriptor: `mtls_dial`, `mtls_stream_client`,
`mtls_stream_server`, `mtls_stream_read`, `mtls_stream_write`,
`mtls_stream_close`.
