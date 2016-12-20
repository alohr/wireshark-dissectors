#include "config.h"

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/to_str.h>

#define UDP_DEFAULT_RANGE "4000"

static range_t *global_beacon_udp_range = NULL;
static range_t *beacon_udp_range = NULL;

static int proto_beacon = -1;
static int hf_beacon_seqnum = -1;
static int hf_beacon_seqnum_ok = -1;
static int hf_beacon_timestamp = -1;
static int hf_beacon_tdiff = -1;

static gint ett_beacon = -1;
static gint ett_beacon_seqnum = -1;
static gint ett_beacon_timestamp = -1;

static expert_field ei_beacon_seqnum_check = EI_INIT;

static dissector_handle_t beacon_handle;

void proto_reg_handoff_beacon(void);

typedef struct {
  gboolean seqnum_check;
} beacon_data_t;

static void to_nstime(nstime_t *nstime, guint64 t)
{
  /* Split into seconds and nanoseconds. */
  nstime->secs = t / 1000000000;
  nstime->nsecs = (int)(t % 1000000000);
}

static int dissect_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
  conversation_t *conversation;
  beacon_data_t *beacon_data;
  nstime_t timestamp;
  nstime_t tdiff;
  guint32 *prev_seqnum;
  guint32 seqnum = tvb_get_letohl(tvb, 0);

  if (!PINFO_FD_VISITED(pinfo)) {
    conversation = find_or_create_conversation(pinfo);
    prev_seqnum = conversation_get_proto_data(conversation, proto_beacon);
    if (prev_seqnum == NULL) {
      prev_seqnum = wmem_alloc0(wmem_file_scope(), sizeof(*prev_seqnum));
      conversation_add_proto_data(conversation, proto_beacon, prev_seqnum);
    }

    beacon_data = wmem_new(wmem_file_scope(), beacon_data_t);
    beacon_data->seqnum_check = *prev_seqnum == 0 || (*prev_seqnum) + 1 == seqnum;

    p_add_proto_data(wmem_file_scope(), pinfo, proto_beacon, 1, beacon_data);

#if 0
    g_print("frame %u prev seqnum %u ok %d\n",
            pinfo->num,
            *prev_seqnum,
            beacon_data->seqnum_check);
#endif

    *prev_seqnum = seqnum;
  }

  to_nstime(&timestamp, tvb_get_letoh64(tvb, 4));

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BEACON");
  col_clear(pinfo->cinfo, COL_INFO);

  col_add_fstr(pinfo->cinfo, COL_INFO, "SeqNum %u, Timestamp %s",
               seqnum,
               abs_time_to_str(wmem_packet_scope(), &timestamp, ABSOLUTE_TIME_LOCAL, 0));

  

  if (tree) {
    proto_item *ti = NULL;
    proto_tree *beacon_tree = NULL;
    proto_tree *seqnum_tree = NULL;
    proto_tree *timestamp_tree = NULL;
    gint offset = 0;

    ti = proto_tree_add_item(tree, proto_beacon, tvb, 0, -1, ENC_NA);
    beacon_tree = proto_item_add_subtree(ti, ett_beacon);

    /* seqnum */
    ti = proto_tree_add_item(beacon_tree, hf_beacon_seqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    seqnum_tree = proto_item_add_subtree(ti, ett_beacon_seqnum);

    beacon_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_beacon, 1);
    ti = proto_tree_add_boolean(seqnum_tree, hf_beacon_seqnum_ok, tvb, offset, 4,
                                beacon_data->seqnum_check);

    if (!beacon_data->seqnum_check) {
      proto_tree_add_expert_format(seqnum_tree, pinfo, &ei_beacon_seqnum_check, tvb, offset, 4,
                                   "Sequence number gap detected");
      expert_add_info_format(pinfo, ti, &ei_beacon_seqnum_check, "This is a TCP duplicate ack");
    }

    PROTO_ITEM_SET_GENERATED(ti);
    offset += 4;

    /* timestamp */
    timestamp_tree = proto_item_add_subtree(ti, ett_beacon_timestamp);

    ti = proto_tree_add_time(beacon_tree, hf_beacon_timestamp, tvb, offset, 8, &timestamp);
    timestamp_tree = proto_item_add_subtree(ti, ett_beacon_timestamp);

    nstime_delta(&tdiff, &pinfo->fd->abs_ts, &timestamp);
    ti = proto_tree_add_time(timestamp_tree, hf_beacon_tdiff, tvb, offset, 8, &tdiff);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  return tvb_captured_length(tvb);
}

static void reinit_beacon(void)
{
  dissector_delete_uint_range("udp.port", beacon_udp_range, beacon_handle);
  g_free(beacon_udp_range);
  beacon_udp_range = range_copy(global_beacon_udp_range);
  dissector_add_uint_range("udp.port", beacon_udp_range, beacon_handle);
}

void proto_register_beacon(void)
{
  module_t *beacon_module = NULL;
  expert_module_t *expert_module = NULL;

  static hf_register_info hf[] = {
    { &hf_beacon_seqnum, {
        "SequenceNumber", "beacon.seqnum",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_beacon_seqnum_ok, {
        "Sequence Number Check", "beacon.seqnum_check",
        FT_BOOLEAN, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_beacon_timestamp, {
        "Timestamp", "beacon.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }},
    { &hf_beacon_tdiff, {
        "Time Difference", "beacon.tdiff",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Difference from capture timestamp", HFILL }},
  };

  static ei_register_info ei[] = {
    { &ei_beacon_seqnum_check, {
        "elf.invalid_segment_size", PI_SEQUENCE, PI_ERROR,
        "Segment size is different then currently parsed bytes", EXPFILL }},
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_beacon,
    &ett_beacon_seqnum,
    &ett_beacon_timestamp,
  };

  proto_beacon = proto_register_protocol(
    "Test Beacon Protocol", /* name */
    "Beacon",               /* short name */
    "beacon"                /* abbrev */
    );

  proto_register_field_array(proto_beacon, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /*
   * Register a preferences module (see section 2.6 of README.developer
   * for more details). Registration of a prefs callback is not required
   * if there are no preferences that affect protocol registration (an example
   * of a preference that would affect registration is a port preference).
   * If the prefs callback is not needed, use NULL instead of
   * proto_reg_handoff_PROTOABBREV in the following.
   */

  beacon_module = prefs_register_protocol(proto_beacon, proto_reg_handoff_beacon);

  range_convert_str(&global_beacon_udp_range, UDP_DEFAULT_RANGE, 65535);

  prefs_register_range_preference(
    beacon_module,
    "udp.port",
    "UDP Ports",
    "UDP Ports range",
    &global_beacon_udp_range, 65535);

  expert_module = expert_register_protocol(proto_beacon);
  expert_register_field_array(expert_module, ei, array_length(ei));
}

void proto_reg_handoff_beacon(void)
{
  beacon_handle = create_dissector_handle(dissect_beacon, proto_beacon);

  reinit_beacon();
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
