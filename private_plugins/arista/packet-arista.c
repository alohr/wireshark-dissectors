/*
 *
 * https://eos.arista.com/timestamping-on-the-7150-series/
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_arista(void);
void proto_reg_handoff_arista(void);

static int proto_arista = -1;
static int hf_arista_hwticks = -1;
static gint ett_arista = -1;

static void
base_hwticks(gchar *buf, guint32 value)
{
  guint32 hwticks = ((value & 0xffffff00) >> 1) | (value & 0x7f);
  g_snprintf(buf, ITEM_LABEL_LENGTH, "%u", hwticks);
}

static int
dissect_arista(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree *ti, *arista_tree;
  guint offset = 0;
  guint trailer_len;

  trailer_len = tvb_reported_length(tvb);

  if (trailer_len != 4)
    return 0;

  if (tvb_captured_length(tvb) < 4)
    return 0;

  ti = proto_tree_add_item(tree, proto_arista, tvb, 0, (trailer_len & 0xb), ENC_NA);
  arista_tree = proto_item_add_subtree(ti, ett_arista);

  proto_tree_add_item(arista_tree, hf_arista_hwticks, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  return offset;
}

void
proto_register_arista(void)
{
  static hf_register_info hf[] = {
    { &hf_arista_hwticks, {
        "HW ticks", "arista.hwticks",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(base_hwticks), 0x0,
        NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_arista,
  };

  proto_arista = proto_register_protocol("Arista ethernet trailer", "Arista", "arista");
  proto_register_field_array(proto_arista, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_arista(void)
{
  heur_dissector_add("eth.trailer", dissect_arista, "Arista ethernet trailer", "arista_eth", proto_arista, HEURISTIC_ENABLE);
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
