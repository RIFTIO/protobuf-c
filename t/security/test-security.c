/*
 * Regression tests for the runtime security fixes backported from upstream
 * protobuf-c into the RIFT fork.  Each test feeds a crafted wire buffer to the
 * unpacker; the fixed runtime must reject it (return NULL) without reading out
 * of bounds.  Run under valgrind (./configure --enable-valgrind-tests) to also
 * catch silent out-of-bounds reads.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "t/test-full.pb-c.h"

/* Discard the runtime's error reports; the tests expect errors. */
static void
quiet_error (ProtobufCInstance *instance, const char *errmsg)
{
  (void) instance;
  (void) errmsg;
}

static ProtobufCInstance *instance;

#define TEST(name) \
  do { printf ("Test: %s... ", #name); fflush (stdout); \
       name (); printf ("done.\n"); } while (0)

/*
 * CVE-2022-48468: a length prefix of 0xFFFFFFFF makes hdr_len + val wrap to a
 * small number and pass the bounds check; len - prefix_len then underflows.
 * In this fork the scanner happened to reject such input anyway (the wrapped
 * length resumes parsing inside the prefix, whose bytes all decode as the
 * invalid wire type 7), so these tests guard the explicit checks rather than
 * reproduce a crash.
 */
static const uint8_t wrapping_length[] = {
  0x0a,                          /* field 1, wire type 2 (length-prefixed) */
  0xff, 0xff, 0xff, 0xff, 0x0f,  /* length 0xFFFFFFFF */
  0x00, 0x00, 0x00, 0x00         /* a few bytes of "payload" */
};

static void
test_length_prefix_wrap_submessage (void)
{
  assert (foo__test_mess_required_message__unpack (
            instance, sizeof wrapping_length, wrapping_length) == NULL);
}

static void
test_length_prefix_wrap_string (void)
{
  assert (foo__test_mess_required_string__unpack (
            instance, sizeof wrapping_length, wrapping_length) == NULL);
}

static void
test_length_prefix_wrap_unknown_field (void)
{
  assert (foo__empty_mess__unpack (
            instance, sizeof wrapping_length, wrapping_length) == NULL);
}

static void
test_length_prefix_over_int_max (void)
{
  static const uint8_t data[] = {
    0x0a,
    0x80, 0x80, 0x80, 0x80, 0x08,  /* length 0x80000000 */
    0x00, 0x00, 0x00, 0x00
  };
  assert (foo__test_mess_required_bytes__unpack (
            instance, sizeof data, data) == NULL);
}

/* Upstream 565118b: field number 0 is invalid. */
static void
test_tag_zero (void)
{
  static const uint8_t data[] = { 0x00, 0x00 };
  assert (foo__empty_mess__unpack (instance, sizeof data, data) == NULL);
}

/* Upstream e2d45cb: zigzag-encoding INT32_MIN/INT64_MIN negated a signed
 * minimum value (undefined behaviour). */
static void
test_zigzag_min (void)
{
  Foo__TestMessRequiredSInt32 m32;
  Foo__TestMessRequiredSInt32 *u32;
  Foo__TestMessRequiredSInt64 m64;
  Foo__TestMessRequiredSInt64 *u64;
  uint8_t buf[16];
  size_t len;

  foo__test_mess_required_sint32__init (&m32);
  m32.test = INT32_MIN;
  len = foo__test_mess_required_sint32__pack (instance, &m32, buf);
  assert (len <= sizeof buf);
  u32 = foo__test_mess_required_sint32__unpack (instance, len, buf);
  assert (u32 != NULL && u32->test == INT32_MIN);
  foo__test_mess_required_sint32__free_unpacked (instance, u32);

  foo__test_mess_required_sint64__init (&m64);
  m64.test = INT64_MIN;
  len = foo__test_mess_required_sint64__pack (instance, &m64, buf);
  assert (len <= sizeof buf);
  u64 = foo__test_mess_required_sint64__unpack (instance, len, buf);
  assert (u64 != NULL && u64->test == INT64_MIN);
  foo__test_mess_required_sint64__free_unpacked (instance, u64);
}

/* Upstream 733ae77: packed bools are varints, which may be longer than one
 * byte; they were parsed one byte per element. */
static void
test_packed_bool_varint (void)
{
  static const uint8_t data[] = {
    0x6a, 0x04,       /* field 13 (test_boolean), length-prefixed, 4 bytes */
    0x81, 0x00,       /* true, as a 2-byte varint */
    0x00,             /* false */
    0x01              /* true */
  };
  Foo__TestMessPacked *m =
    foo__test_mess_packed__unpack (instance, sizeof data, data);
  assert (m != NULL);
  assert (m->n_test_boolean == 3);
  assert (m->test_boolean[0] && !m->test_boolean[1] && m->test_boolean[2]);
  foo__test_mess_packed__free_unpacked (instance, m);
}

int
main (void)
{
  ProtobufCInstance quiet = *protobuf_c_instance_get (NULL);
  quiet.error = quiet_error;
  instance = &quiet;

  TEST (test_length_prefix_wrap_submessage);
  TEST (test_length_prefix_wrap_string);
  TEST (test_length_prefix_wrap_unknown_field);
  TEST (test_length_prefix_over_int_max);
  TEST (test_tag_zero);
  TEST (test_zigzag_min);
  TEST (test_packed_bool_varint);
  return 0;
}
