#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

#define UDP_DEFAULT_RANGE "4000"

static range_t *global_beacon_udp_range = NULL;
static range_t *beacon_udp_range = NULL;

static int proto_beacon = -1;
static int hf_beacon_seqnum = -1;
static int hf_beacon_timestamp = -1;
static int hf_beacon_tdiff = -1;

static gint ett_beacon = -1;
static gint ett_beacon_timestamp = -1;

static dissector_handle_t beacon_handle;

void proto_reg_handoff_beacon(void);


static void nstimestamp_to_nstime(nstime_t *nstime, guint64 nstimestamp)
{
  /* Split into seconds and nanoseconds. */
  nstime->secs = nstimestamp / 1000000000;
  nstime->nsecs = (int)(nstimestamp % 1000000000);
}

static int dissect_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
  proto_tree *timestamp_tree;
  guint32 seqnum = tvb_get_letohl(tvb, 0);
  guint64 t = tvb_get_letoh64(tvb, 4);
  nstime_t nstimestamp = {};
  nstime_t tdiff;

  nstimestamp_to_nstime(&nstimestamp, t);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BEACON");
  col_clear(pinfo->cinfo, COL_INFO);

  col_add_fstr(pinfo->cinfo, COL_INFO, "SeqNum %u, Timestamp %s",
               seqnum,
               abs_time_to_str(wmem_packet_scope(), &nstimestamp, ABSOLUTE_TIME_LOCAL, 0));

  if (tree) {
    proto_item *ti = NULL;
    proto_tree *beacon_tree = NULL;
    gint offset = 0;

    ti = proto_tree_add_item(tree, proto_beacon, tvb, 0, -1, ENC_NA);
    beacon_tree = proto_item_add_subtree(ti, ett_beacon);

    proto_tree_add_item(beacon_tree, hf_beacon_seqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // proto_tree_add_item(beacon_tree, hf_beacon_timestamp, tvb, offset, 8, ENC_TIME_NANOS_TIME_T|ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_time(beacon_tree, hf_beacon_timestamp, tvb, offset, 8, &nstimestamp);
    timestamp_tree = proto_item_add_subtree(ti, ett_beacon_timestamp);

    nstime_delta(&tdiff, &pinfo->fd->abs_ts, &nstimestamp);
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

  static hf_register_info hf[] = {
    { &hf_beacon_seqnum, {
        "SequenceNumber", "beacon.SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }},
    { &hf_beacon_timestamp, {
        "Timestamp", "beacon.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        "", HFILL }},
    { &hf_beacon_tdiff, {
        "Time Difference", "beacon.tdiff",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Difference from capture timestamp", HFILL }},
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_beacon,
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
