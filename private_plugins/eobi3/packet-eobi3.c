#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

#include "packet-eobi3.h"
#include "marketsegments.h"

#define UDP_DEFAULT_RANGE "59000,59001,59032,59033"

static range_t *global_eobi3_udp_range = NULL;
static range_t *eobi3_udp_range = NULL;

static int proto_eobi3 = -1;

static int hf_eobi3_packetheader = -1;
static int hf_eobi3_heartbeat = -1;
static int hf_eobi3_orderadd = -1;
static int hf_eobi3_ordermodify = -1;
static int hf_eobi3_orderdelete = -1;
static int hf_eobi3_ordermassdelete = -1;
static int hf_eobi3_fullorderexecution = -1;
static int hf_eobi3_partialorderexecution = -1;
static int hf_eobi3_ordermodifysameprio = -1;
static int hf_eobi3_tradereversal = -1;
static int hf_eobi3_tradereport = -1;
static int hf_eobi3_executionsummary = -1;
static int hf_eobi3_productstatechange = -1;
static int hf_eobi3_instrumentstatechange = -1;
static int hf_eobi3_addcomplexinstrument = -1;
static int hf_eobi3_auctionbbo = -1;
static int hf_eobi3_auctionclearingprice = -1;
static int hf_eobi3_crossrequest = -1;
static int hf_eobi3_quoterequest = -1;
static int hf_eobi3_topofbook = -1;
static int hf_eobi3_productsummary = -1;
static int hf_eobi3_instrumentsummary = -1;
static int hf_eobi3_snapshotorder = -1;

static int hf_eobi3_trdregtsexecutiontime = -1;
static int hf_eobi3_requesttime = -1;
static int hf_eobi3_mdentrypx = -1;
static int hf_eobi3_tradecondition = -1;
static int hf_eobi3_totnoorders = -1;
static int hf_eobi3_securityidsource = -1;
static int hf_eobi3_marketsegmentid = -1;
static int hf_eobi3_aggressortimestamp = -1;
static int hf_eobi3_securitytradingstatus = -1;
static int hf_eobi3_prevprice = -1;
static int hf_eobi3_displayqty = -1;
static int hf_eobi3_nomdentries = -1;
static int hf_eobi3_trdregtsprevtimepriority = -1;
static int hf_eobi3_nolegs = -1;
static int hf_eobi3_partitionid = -1;
static int hf_eobi3_securityupdateaction = -1;
static int hf_eobi3_tradingsessionsubid = -1;
static int hf_eobi3_bodylen = -1;
static int hf_eobi3_mdupdateaction = -1;
static int hf_eobi3_price = -1;
static int hf_eobi3_lastqty = -1;
static int hf_eobi3_applseqresetindicator = -1;
static int hf_eobi3_mdentrytype = -1;
static int hf_eobi3_side = -1;
static int hf_eobi3_pad1 = -1;
static int hf_eobi3_impliedmarketindicator = -1;
static int hf_eobi3_pad3 = -1;
static int hf_eobi3_securityid = -1;
static int hf_eobi3_pad5 = -1;
static int hf_eobi3_legsecurityidsource = -1;
static int hf_eobi3_pad7 = -1;
static int hf_eobi3_templateid = -1;
static int hf_eobi3_transacttime = -1;
static int hf_eobi3_completionindicator = -1;
static int hf_eobi3_applseqnum = -1;
static int hf_eobi3_pad4 = -1;
static int hf_eobi3_legsecurityid = -1;
static int hf_eobi3_pad2 = -1;
static int hf_eobi3_securitystatus = -1;
static int hf_eobi3_restinghiddenqty = -1;
static int hf_eobi3_prevdisplayqty = -1;
static int hf_eobi3_trdmatchid = -1;
static int hf_eobi3_mdreportevent = -1;
static int hf_eobi3_tradsesstatus = -1;
static int hf_eobi3_pad6 = -1;
static int hf_eobi3_lastmsgseqnumprocessed = -1;
static int hf_eobi3_lastpx = -1;
static int hf_eobi3_msgseqnum = -1;
static int hf_eobi3_msgtype = -1;
static int hf_eobi3_restingcxlqty = -1;
static int hf_eobi3_nomarketsegments = -1;
static int hf_eobi3_trdregtstimepriority = -1;
static int hf_eobi3_matchtype = -1;
static int hf_eobi3_offerpx = -1;
static int hf_eobi3_legratioqty = -1;
static int hf_eobi3_legsymbol = -1;
static int hf_eobi3_execid = -1;
static int hf_eobi3_lastupdatetime = -1;
static int hf_eobi3_marketdatatype = -1;
static int hf_eobi3_aggressorside = -1;
static int hf_eobi3_productcomplex = -1;
static int hf_eobi3_legside = -1;
static int hf_eobi3_securitysubtype = -1;
static int hf_eobi3_securitytype = -1;
static int hf_eobi3_trdregtstimein = -1;
static int hf_eobi3_mdentrysize = -1;
static int hf_eobi3_tradsesevent = -1;
static int hf_eobi3_fastmarketindicator = -1;
static int hf_eobi3_matchsubtype = -1;
static int hf_eobi3_bidpx = -1;
static int hf_eobi3_tradingsessionid = -1;

static int ett_eobi3 = -1;
static int ett_eobi3_packetheader = -1;
static int ett_eobi3_heartbeat = -1;
static int ett_eobi3_orderadd = -1;
static int ett_eobi3_ordermodify = -1;
static int ett_eobi3_orderdelete = -1;
static int ett_eobi3_ordermassdelete = -1;
static int ett_eobi3_fullorderexecution = -1;
static int ett_eobi3_partialorderexecution = -1;
static int ett_eobi3_ordermodifysameprio = -1;
static int ett_eobi3_tradereversal = -1;
static int ett_eobi3_tradereport = -1;
static int ett_eobi3_executionsummary = -1;
static int ett_eobi3_productstatechange = -1;
static int ett_eobi3_instrumentstatechange = -1;
static int ett_eobi3_addcomplexinstrument = -1;
static int ett_eobi3_auctionbbo = -1;
static int ett_eobi3_auctionclearingprice = -1;
static int ett_eobi3_crossrequest = -1;
static int ett_eobi3_quoterequest = -1;
static int ett_eobi3_topofbook = -1;
static int ett_eobi3_productsummary = -1;
static int ett_eobi3_instrumentsummary = -1;
static int ett_eobi3_snapshotorder = -1;

static dissector_handle_t eobi3_handle;

static const value_string templatenames[] = {
    { 13001, "Heartbeat" },
    { 13004, "PacketHeader" },
    { 13100, "OrderAdd" },
    { 13101, "OrderModify" },
    { 13102, "OrderDelete" },
    { 13103, "OrderMassDelete" },
    { 13104, "FullOrderExecution" },
    { 13105, "PartialOrderExecution" },
    { 13106, "OrderModifySamePrio" },
    { 13200, "TradeReversal" },
    { 13201, "TradeReport" },
    { 13202, "ExecutionSummary" },
    { 13300, "ProductStateChange" },
    { 13301, "InstrumentStateChange" },
    { 13400, "AddComplexInstrument" },
    { 13500, "AuctionBBO" },
    { 13501, "AuctionClearingPrice" },
    { 13502, "CrossRequest" },
    { 13503, "QuoteRequest" },
    { 13504, "TopOfBook" },
    { 13600, "ProductSummary" },
    { 13601, "InstrumentSummary" },
    { 13602, "SnapshotOrder" },
    { 0, NULL },
};

static const value_string aggressorsidenames[] = {
    { 1, "Buy" },
    { 2, "Sell" },
    { 0, NULL }
};

static const value_string applseqresetindicatornames[] = {
    { 0, "NoReset" },
    { 1, "Reset" },
    { 0, NULL }
};

static const value_string completionindicatornames[] = {
    { 0, "Incomplete" },
    { 1, "Complete" },
    { 0, NULL }
};

static const value_string fastmarketindicatornames[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};

static const value_string impliedmarketindicatornames[] = {
    { 0, "NotImplied" },
    { 3, "ImpliedInOut" },
    { 0, NULL }
};

static const value_string legsidenames[] = {
    { 1, "Buy" },
    { 2, "Sell" },
    { 0, NULL }
};

static const value_string mdentrytypenames[] = {
    { 2, "Trade" },
    { 4, "OpeningPrice" },
    { 5, "ClosingPrice" },
    { 7, "HighPrice" },
    { 8, "LowPrice" },
    { 66, "TradeVolume" },
    { 101, "PreviousClosingPrice" },
    { 200, "OpeningAuction" },
    { 201, "IntradayAuction" },
    { 202, "CircuitBreakerAuction" },
    { 203, "ClosingAuction" },
    { 0, NULL }
};

static const value_string mdreporteventnames[] = {
    { 0, "ScopeDefinition" },
    { 0, NULL }
};

static const value_string mdupdateactionnames[] = {
    { 0, "New" },
    { 1, "Change" },
    { 2, "Delete" },
    { 5, "Overlay" },
    { 0, NULL }
};

static const value_string marketdatatypenames[] = {
    { 1, "OrderBookMaintenance" },
    { 2, "OrderBookExecution" },
    { 3, "TradeReversal" },
    { 4, "TradeReport" },
    { 5, "AuctionBBO" },
    { 6, "AuctionClearingPrice" },
    { 7, "CrossTradeAnnouncement" },
    { 8, "QuoteRequest" },
    { 9, "MarketSegmentSnapshot" },
    { 10, "SingleInstrumentSnapshot" },
    { 11, "OrderBookSnapshot" },
    { 12, "MatchEvent" },
    { 13, "TopOfBook" },
    { 0, NULL }
};

static const value_string matchsubtypenames[] = {
    { 1, "OpeningAuction" },
    { 2, "ClosingAuction" },
    { 3, "IntradayAuction" },
    { 4, "CircuitBreakerAuction" },
    { 0, NULL }
};

static const value_string matchtypenames[] = {
    { 3, "ConfirmedTradeReport" },
    { 5, "CrossAuction" },
    { 7, "CallAuction" },
    { 0, NULL }
};

static const value_string nomarketsegmentsnames[] = {
    { 1, "One" },
    { 0, NULL }
};

static const value_string productcomplexnames[] = {
    { 5, "FuturesSpread" },
    { 6, "InterProductSpread" },
    { 7, "StandardFuturesStrategy" },
    { 8, "PackAndBundle" },
    { 9, "Strip" },
    { 0, NULL }
};

static const value_string securitystatusnames[] = {
    { 1, "Active" },
    { 2, "Inactive" },
    { 4, "Expired" },
    { 9, "Suspended" },
    { 0, NULL }
};

static const value_string securitytradingstatusnames[] = {
    { 200, "Closed" },
    { 201, "Restricted" },
    { 202, "Book" },
    { 203, "Continuous" },
    { 204, "OpeningAuction" },
    { 205, "OpeningAuctionFreeze" },
    { 206, "IntradayAuction" },
    { 207, "IntradayAuctionFreeze" },
    { 208, "CircuitBreakerAuction" },
    { 209, "CircuitBreakerAuctionFreeze" },
    { 210, "ClosingAuction" },
    { 211, "ClosingAuctionFreeze" },
    { 0, NULL }
};

static const value_string sidenames[] = {
    { 1, "Buy" },
    { 2, "Sell" },
    { 0, NULL }
};

static const value_string tradseseventnames[] = {
    { 0, "TBD" },
    { 3, "StatusChange" },
    { 0, NULL }
};

static const value_string tradsesstatusnames[] = {
    { 1, "Halted" },
    { 2, "Open" },
    { 3, "Closed" },
    { 0, NULL }
};

static const value_string tradeconditionnames[] = {
    { 1, "ImpliedTrade" },
    { 0, NULL }
};

static const value_string tradingsessionidnames[] = {
    { 1, "Day" },
    { 3, "Morning" },
    { 5, "Evening" },
    { 7, "Holiday" },
    { 0, NULL }
};

static const value_string tradingsessionsubidnames[] = {
    { 1, "PreTrading" },
    { 3, "Trading" },
    { 4, "Closing" },
    { 5, "PostTrading" },
    { 7, "Quiescent" },
    { 0, NULL }
};

void proto_reg_handoff_eobi3(void);

static void nstimestamp_to_nstime(nstime_t *nstime, guint64 nstimestamp)
{
    /* Split into seconds and nanoseconds. */
    nstime->secs = nstimestamp / 1000000000;
    nstime->nsecs = (int)(nstimestamp % 1000000000);
}

static void scan_templateids(tvbuff_t* tvb, packet_info* pinfo)
{
    gint offset = tvb_get_letohs(tvb, 0);
    gint offset_end = tvb_captured_length(tvb);
    guint16 current_templateid = tvb_get_letohs(tvb, offset + 2);
    gint current_counter = 0;

    while (offset < offset_end) {
	guint16 bodylen = tvb_get_letohs(tvb, offset);
	guint16 templateid = tvb_get_letohs(tvb, offset + 2);

	if (current_templateid == templateid) {
	    current_counter++;
	} else {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s#%u",
			    val_to_str(current_templateid, templatenames, "Unkown(0x%04x)"),
			    current_counter);
	    current_templateid = templateid;
	    current_counter = 0;
	}

 	offset += bodylen;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s#%u",
		    val_to_str(current_templateid, templatenames, "Unkown(0x%04x)"),
		    current_counter);
}

static gint dissect_addcomplexinstrument(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_addcomplexinstrument);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securitysubtype, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_productcomplex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_impliedmarketindicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_nolegs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_legsymbol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_pad4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_legsecurityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_legratioqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_legside, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
}

static gint dissect_auctionbbo(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_auctionbbo);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_bidpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_offerpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_auctionclearingprice(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_auctionclearingprice);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_lastpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_crossrequest(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_crossrequest);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_lastqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_pad4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;

    return offset;
}

static gint dissect_executionsummary(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_executionsummary);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_aggressortimestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_requesttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_execid, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_lastqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_aggressorside, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_tradecondition, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_lastpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_restinghiddenqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_restingcxlqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static gint dissect_fullorderexecution(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_fullorderexecution);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad7, tvb, offset, 7, ENC_LITTLE_ENDIAN);
    offset += 7;
    proto_tree_add_item(tree, hf_eobi3_price, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdmatchid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_heartbeat(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_heartbeat);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastmsgseqnumprocessed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_pad4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static gint dissect_instrumentstatechange(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_instrumentstatechange);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securitystatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_securitytradingstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_fastmarketindicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad5, tvb, offset, 5, ENC_LITTLE_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;

    return offset;
}

static gint dissect_instrumentsummary(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_instrumentsummary);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_lastupdatetime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtsexecutiontime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_totnoorders, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_securitystatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_securitytradingstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_fastmarketindicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_nomdentries, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_mdentrypx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_mdentrysize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_mdentrytype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
}

static gint dissect_orderadd(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_orderadd);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimein, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_displayqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    proto_tree_add_item(tree, hf_eobi3_price, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_orderdelete(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_orderdelete);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimein, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_displayqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    proto_tree_add_item(tree, hf_eobi3_price, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_ordermassdelete(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_ordermassdelete);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;

    return offset;
}

static gint dissect_ordermodify(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_ordermodify);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimein, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtsprevtimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_prevprice, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_prevdisplayqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_pad4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_displayqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    proto_tree_add_item(tree, hf_eobi3_price, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_ordermodifysameprio(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_ordermodifysameprio);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimein, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_prevdisplayqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_pad4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_displayqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    proto_tree_add_item(tree, hf_eobi3_price, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_packetheader(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_packetheader);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_applseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_marketsegmentid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_partitionid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_completionindicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_applseqresetindicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad5, tvb, offset, 5, ENC_LITTLE_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;

    return offset;
}

static gint dissect_partialorderexecution(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_partialorderexecution);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad7, tvb, offset, 7, ENC_LITTLE_ENDIAN);
    offset += 7;
    proto_tree_add_item(tree, hf_eobi3_price, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdmatchid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_productstatechange(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_productstatechange);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_tradingsessionid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_tradingsessionsubid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_tradsesstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_fastmarketindicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;

    return offset;
}

static gint dissect_productsummary(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_productsummary);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastmsgseqnumprocessed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_tradingsessionid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_tradingsessionsubid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_tradsesstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_fastmarketindicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

static gint dissect_quoterequest(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_quoterequest);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_lastqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;

    return offset;
}

static gint dissect_snapshotorder(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_snapshotorder);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_trdregtstimepriority, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_displayqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    proto_tree_add_item(tree, hf_eobi3_price, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_topofbook(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_topofbook);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_bidpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_offerpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint dissect_tradereport(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_tradereport);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdmatchid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_matchtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_matchsubtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad6, tvb, offset, 6, ENC_LITTLE_ENDIAN);
    offset += 6;

    return offset;
}

static gint dissect_tradereversal(tvbuff_t* tvb, proto_item* ti, gint offset)
{
    proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_tradereversal);

    proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_templateid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eobi3_msgseqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_securityid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_transacttime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdmatchid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastqty, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_lastpx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_trdregtsexecutiontime, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_nomdentries, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad7, tvb, offset, 7, ENC_LITTLE_ENDIAN);
    offset += 7;
    proto_tree_add_item(tree, hf_eobi3_mdentrypx, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_eobi3_mdentrysize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eobi3_mdentrytype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_eobi3_pad3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
}

static int dissect_eobi3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
    /* guint16 bodylen = tvb_get_letohs(tvb, 0); */
    /* guint16 templateid = tvb_get_letohs(tvb, 2); */
    guint32 applseqnum = tvb_get_letohl(tvb, 8);
    guint32 marketsegmentid = tvb_get_letohl(tvb, 12);

    guint64 t = tvb_get_letoh64(tvb, 24);
    nstime_t transacttime = {};

    nstimestamp_to_nstime(&transacttime, t);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EOBI3");
    col_clear(pinfo->cinfo, COL_INFO);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, ApplSeqNum %u, TransactTime %s",
		 val_to_str(marketsegmentid, marketsegments, "Unkown(%u)"),
		 applseqnum,
    		 abs_time_to_str(wmem_packet_scope(), &transacttime, ABSOLUTE_TIME_ISO_DATE_LOCAL, 0));

    col_set_fence(pinfo->cinfo, COL_INFO);
    scan_templateids(tvb, pinfo);

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *eobi3_tree = NULL;
	gint offset = 0;
	gint offset_end = tvb_captured_length(tvb);

        ti = proto_tree_add_item(tree, proto_eobi3, tvb, 0, -1, ENC_NA);
        eobi3_tree = proto_item_add_subtree(ti, ett_eobi3);

	while (offset < offset_end) {
	    guint16 bodylen = tvb_get_letohs(tvb, offset);
	    guint16 templateid = tvb_get_letohs(tvb, offset + 2);
	    proto_item *sub_ti = NULL;

	    switch (templateid) {
	    case EOBI_PACKETHEADER:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_packetheader, tvb, offset, bodylen, ENC_NA);
		dissect_packetheader(tvb, sub_ti, offset);
		break;
	    case EOBI_HEARTBEAT:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_heartbeat, tvb, offset, bodylen, ENC_NA);
		dissect_heartbeat(tvb, sub_ti, offset);
		break;
	    case EOBI_ORDERADD:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_orderadd, tvb, offset, bodylen, ENC_NA);
		dissect_orderadd(tvb, sub_ti, offset);
		break;
	    case EOBI_ORDERMODIFY:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_ordermodify, tvb, offset, bodylen, ENC_NA);
		dissect_ordermodify(tvb, sub_ti, offset);
		break;
	    case EOBI_ORDERDELETE:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_orderdelete, tvb, offset, bodylen, ENC_NA);
		dissect_orderdelete(tvb, sub_ti, offset);
		break;
	    case EOBI_ORDERMASSDELETE:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_ordermassdelete, tvb, offset, bodylen, ENC_NA);
		dissect_ordermassdelete(tvb, sub_ti, offset);
		break;
	    case EOBI_FULLORDEREXECUTION:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_fullorderexecution, tvb, offset, bodylen, ENC_NA);
		dissect_fullorderexecution(tvb, sub_ti, offset);
		break;
	    case EOBI_PARTIALORDEREXECUTION:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_partialorderexecution, tvb, offset, bodylen, ENC_NA);
		dissect_partialorderexecution(tvb, sub_ti, offset);
		break;
	    case EOBI_ORDERMODIFYSAMEPRIO:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_ordermodifysameprio, tvb, offset, bodylen, ENC_NA);
		dissect_ordermodifysameprio(tvb, sub_ti, offset);
		break;
	    case EOBI_TRADEREVERSAL:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_tradereversal, tvb, offset, bodylen, ENC_NA);
		dissect_tradereversal(tvb, sub_ti, offset);
		break;
	    case EOBI_TRADEREPORT:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_tradereport, tvb, offset, bodylen, ENC_NA);
		dissect_tradereport(tvb, sub_ti, offset);
		break;
	    case EOBI_EXECUTIONSUMMARY:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_executionsummary, tvb, offset, bodylen, ENC_NA);
		dissect_executionsummary(tvb, sub_ti, offset);
		break;
	    case EOBI_PRODUCTSTATECHANGE:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_productstatechange, tvb, offset, bodylen, ENC_NA);
		dissect_productstatechange(tvb, sub_ti, offset);
		break;
	    case EOBI_INSTRUMENTSTATECHANGE:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_instrumentstatechange, tvb, offset, bodylen, ENC_NA);
		dissect_instrumentstatechange(tvb, sub_ti, offset);
		break;
	    case EOBI_ADDCOMPLEXINSTRUMENT:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_addcomplexinstrument, tvb, offset, bodylen, ENC_NA);
		dissect_addcomplexinstrument(tvb, sub_ti, offset);
		break;
	    case EOBI_AUCTIONBBO:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_auctionbbo, tvb, offset, bodylen, ENC_NA);
		dissect_auctionbbo(tvb, sub_ti, offset);
		break;
	    case EOBI_AUCTIONCLEARINGPRICE:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_auctionclearingprice, tvb, offset, bodylen, ENC_NA);
		dissect_auctionclearingprice(tvb, sub_ti, offset);
		break;
	    case EOBI_CROSSREQUEST:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_crossrequest, tvb, offset, bodylen, ENC_NA);
		dissect_crossrequest(tvb, sub_ti, offset);
		break;
	    case EOBI_QUOTEREQUEST:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_quoterequest, tvb, offset, bodylen, ENC_NA);
		dissect_quoterequest(tvb, sub_ti, offset);
		break;
	    case EOBI_TOPOFBOOK:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_topofbook, tvb, offset, bodylen, ENC_NA);
		dissect_topofbook(tvb, sub_ti, offset);
		break;
	    case EOBI_PRODUCTSUMMARY:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_productsummary, tvb, offset, bodylen, ENC_NA);
		dissect_productsummary(tvb, sub_ti, offset);
		break;
	    case EOBI_INSTRUMENTSUMMARY:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_instrumentsummary, tvb, offset, bodylen, ENC_NA);
		dissect_instrumentsummary(tvb, sub_ti, offset);
		break;
	    case EOBI_SNAPSHOTORDER:
		sub_ti = proto_tree_add_item(
		    eobi3_tree, hf_eobi3_snapshotorder, tvb, offset, bodylen, ENC_NA);
		dissect_snapshotorder(tvb, sub_ti, offset);
		break;
	    }

	    offset += bodylen;
	}
    }

    return tvb_captured_length(tvb);
}

static void reinit_eobi3(void)
{
    dissector_delete_uint_range("udp.port", eobi3_udp_range, eobi3_handle);
    g_free(eobi3_udp_range);
    eobi3_udp_range = range_copy(global_eobi3_udp_range);
    dissector_add_uint_range("udp.port", eobi3_udp_range, eobi3_handle);
}

void proto_register_eobi3(void)
{
    module_t *eobi3_module = NULL;

    static hf_register_info hf[] = {
	{ &hf_eobi3_packetheader,
	  { "PacketHeader", "eobi3.PacketHeader", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_heartbeat,
	  { "Heartbeat", "eobi3.Heartbeat", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_orderadd,
	  { "OrderAdd", "eobi3.OrderAdd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_ordermodify,
	  { "OrderModify", "eobi3.OrderModify", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_orderdelete,
	  { "OrderDelete", "eobi3.OrderDelete", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_ordermassdelete,
	  { "OrderMassDelete", "eobi3.OrderMassDelete", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_fullorderexecution,
	  { "FullOrderExecution", "eobi3.FullOrderExecution", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_partialorderexecution,
	  { "PartialOrderExecution", "eobi3.PartialOrderExecution", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_ordermodifysameprio,
	  { "OrderModifySamePrio", "eobi3.OrderModifySamePrio", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_tradereversal,
	  { "TradeReversal", "eobi3.TradeReversal", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_tradereport,
	  { "TradeReport", "eobi3.TradeReport", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_executionsummary,
	  { "ExecutionSummary", "eobi3.ExecutionSummary", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_productstatechange,
	  { "ProductStateChange", "eobi3.ProductStateChange", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_instrumentstatechange,
	  { "InstrumentStateChange", "eobi3.InstrumentStateChange", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_addcomplexinstrument,
	  { "AddComplexInstrument", "eobi3.AddComplexInstrument", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_auctionbbo,
	  { "AuctionBBO", "eobi3.AuctionBBO", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_auctionclearingprice,
	  { "AuctionClearingPrice", "eobi3.AuctionClearingPrice", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_crossrequest,
	  { "CrossRequest", "eobi3.CrossRequest", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_quoterequest,
	  { "QuoteRequest", "eobi3.QuoteRequest", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_topofbook,
	  { "TopOfBook", "eobi3.TopOfBook", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_productsummary,
	  { "ProductSummary", "eobi3.ProductSummary", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_instrumentsummary,
	  { "InstrumentSummary", "eobi3.InstrumentSummary", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{ &hf_eobi3_snapshotorder,
	  { "SnapshotOrder", "eobi3.SnapshotOrder", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	/*
	 * fields
	 */
    {
      &hf_eobi3_trdregtsexecutiontime,
      { "TrdRegTSExecutionTime", "eobi3.TrdRegTSExecutionTime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_requesttime,
      { "RequestTime", "eobi3.RequestTime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_mdentrypx,
      { "MDEntryPx", "eobi3.MDEntryPx", FT_INT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_tradecondition,
      { "TradeCondition", "eobi3.TradeCondition", FT_INT8, BASE_DEC, VALS(tradeconditionnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_totnoorders,
      { "TotNoOrders", "eobi3.TotNoOrders", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_securityidsource,
      { "SecurityIDSource", "eobi3.SecurityIDSource", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_marketsegmentid,
      { "MarketSegmentID", "eobi3.MarketSegmentID", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_aggressortimestamp,
      { "AggressorTimestamp", "eobi3.AggressorTimestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_securitytradingstatus,
      { "SecurityTradingStatus", "eobi3.SecurityTradingStatus", FT_INT8, BASE_DEC, VALS(securitytradingstatusnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_prevprice,
      { "PrevPrice", "eobi3.PrevPrice", FT_INT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_displayqty,
      { "DisplayQty", "eobi3.DisplayQty", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_nomdentries,
      { "NoMDEntries", "eobi3.NoMDEntries", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_trdregtsprevtimepriority,
      { "TrdRegTSPrevTimePriority", "eobi3.TrdRegTSPrevTimePriority", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_nolegs,
      { "NoLegs", "eobi3.NoLegs", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_partitionid,
      { "PartitionID", "eobi3.PartitionID", FT_INT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_securityupdateaction,
      { "SecurityUpdateAction", "eobi3.SecurityUpdateAction", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_tradingsessionsubid,
      { "TradingSessionSubID", "eobi3.TradingSessionSubID", FT_INT8, BASE_DEC, VALS(tradingsessionsubidnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_bodylen,
      { "BodyLen", "eobi3.BodyLen", FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_mdupdateaction,
      { "MDUpdateAction", "eobi3.MDUpdateAction", FT_INT8, BASE_DEC, VALS(mdupdateactionnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_price,
      { "Price", "eobi3.Price", FT_INT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_lastqty,
      { "LastQty", "eobi3.LastQty", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_applseqresetindicator,
      { "ApplSeqResetIndicator", "eobi3.ApplSeqResetIndicator", FT_INT8, BASE_DEC, VALS(applseqresetindicatornames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_mdentrytype,
      { "MDEntryType", "eobi3.MDEntryType", FT_INT8, BASE_DEC, VALS(mdentrytypenames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_side,
      { "Side", "eobi3.Side", FT_INT8, BASE_DEC, VALS(sidenames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_pad1,
      { "Pad1", "eobi3.Pad1", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_impliedmarketindicator,
      { "ImpliedMarketIndicator", "eobi3.ImpliedMarketIndicator", FT_INT8, BASE_DEC, VALS(impliedmarketindicatornames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_pad3,
      { "Pad3", "eobi3.Pad3", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_securityid,
      { "SecurityID", "eobi3.SecurityID", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_pad5,
      { "Pad5", "eobi3.Pad5", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_legsecurityidsource,
      { "LegSecurityIDSource", "eobi3.LegSecurityIDSource", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_pad7,
      { "Pad7", "eobi3.Pad7", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_templateid,
      { "TemplateID", "eobi3.TemplateID", FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_transacttime,
      { "TransactTime", "eobi3.TransactTime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_completionindicator,
      { "CompletionIndicator", "eobi3.CompletionIndicator", FT_INT8, BASE_DEC, VALS(completionindicatornames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_applseqnum,
      { "ApplSeqNum", "eobi3.ApplSeqNum", FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_pad4,
      { "Pad4", "eobi3.Pad4", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_legsecurityid,
      { "LegSecurityID", "eobi3.LegSecurityID", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_pad2,
      { "Pad2", "eobi3.Pad2", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_securitystatus,
      { "SecurityStatus", "eobi3.SecurityStatus", FT_INT8, BASE_DEC, VALS(securitystatusnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_restinghiddenqty,
      { "RestingHiddenQty", "eobi3.RestingHiddenQty", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_prevdisplayqty,
      { "PrevDisplayQty", "eobi3.PrevDisplayQty", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_trdmatchid,
      { "TrdMatchID", "eobi3.TrdMatchID", FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_mdreportevent,
      { "MDReportEvent", "eobi3.MDReportEvent", FT_INT8, BASE_DEC, VALS(mdreporteventnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_tradsesstatus,
      { "TradSesStatus", "eobi3.TradSesStatus", FT_INT8, BASE_DEC, VALS(tradsesstatusnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_pad6,
      { "Pad6", "eobi3.Pad6", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_lastmsgseqnumprocessed,
      { "LastMsgSeqNumProcessed", "eobi3.LastMsgSeqNumProcessed", FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_lastpx,
      { "LastPx", "eobi3.LastPx", FT_INT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_msgseqnum,
      { "MsgSeqNum", "eobi3.MsgSeqNum", FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_msgtype,
      { "MsgType", "eobi3.MsgType", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_restingcxlqty,
      { "RestingCxlQty", "eobi3.RestingCxlQty", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_nomarketsegments,
      { "NoMarketSegments", "eobi3.NoMarketSegments", FT_INT8, BASE_DEC, VALS(nomarketsegmentsnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_trdregtstimepriority,
      { "TrdRegTSTimePriority", "eobi3.TrdRegTSTimePriority", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_matchtype,
      { "MatchType", "eobi3.MatchType", FT_INT8, BASE_DEC, VALS(matchtypenames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_offerpx,
      { "OfferPx", "eobi3.OfferPx", FT_INT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_legratioqty,
      { "LegRatioQty", "eobi3.LegRatioQty", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_legsymbol,
      { "LegSymbol", "eobi3.LegSymbol", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_execid,
      { "ExecID", "eobi3.ExecID", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_lastupdatetime,
      { "LastUpdateTime", "eobi3.LastUpdateTime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_marketdatatype,
      { "MarketDataType", "eobi3.MarketDataType", FT_INT8, BASE_DEC, VALS(marketdatatypenames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_aggressorside,
      { "AggressorSide", "eobi3.AggressorSide", FT_INT8, BASE_DEC, VALS(aggressorsidenames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_productcomplex,
      { "ProductComplex", "eobi3.ProductComplex", FT_INT8, BASE_DEC, VALS(productcomplexnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_legside,
      { "LegSide", "eobi3.LegSide", FT_INT8, BASE_DEC, VALS(legsidenames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_securitysubtype,
      { "SecuritySubType", "eobi3.SecuritySubType", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_securitytype,
      { "SecurityType", "eobi3.SecurityType", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_trdregtstimein,
      { "TrdRegTSTimeIn", "eobi3.TrdRegTSTimeIn", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_ISO_DATE_LOCAL, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_mdentrysize,
      { "MDEntrySize", "eobi3.MDEntrySize", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_tradsesevent,
      { "TradSesEvent", "eobi3.TradSesEvent", FT_INT8, BASE_DEC, VALS(tradseseventnames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_fastmarketindicator,
      { "FastMarketIndicator", "eobi3.FastMarketIndicator", FT_INT8, BASE_DEC, VALS(fastmarketindicatornames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_matchsubtype,
      { "MatchSubType", "eobi3.MatchSubType", FT_INT8, BASE_DEC, VALS(matchsubtypenames), 0x0, "", HFILL }
    },
    {
      &hf_eobi3_bidpx,
      { "BidPx", "eobi3.BidPx", FT_INT64, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    {
      &hf_eobi3_tradingsessionid,
      { "TradingSessionID", "eobi3.TradingSessionID", FT_INT8, BASE_DEC, VALS(tradingsessionidnames), 0x0, "", HFILL }
    },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
	&ett_eobi3,
	&ett_eobi3_packetheader,
	&ett_eobi3_heartbeat,
	&ett_eobi3_orderadd,
	&ett_eobi3_ordermodify,
	&ett_eobi3_orderdelete,
	&ett_eobi3_ordermassdelete,
	&ett_eobi3_fullorderexecution,
	&ett_eobi3_partialorderexecution,
	&ett_eobi3_ordermodifysameprio,
	&ett_eobi3_tradereversal,
	&ett_eobi3_tradereport,
	&ett_eobi3_executionsummary,
	&ett_eobi3_productstatechange,
	&ett_eobi3_instrumentstatechange,
	&ett_eobi3_addcomplexinstrument,
	&ett_eobi3_auctionbbo,
	&ett_eobi3_auctionclearingprice,
	&ett_eobi3_crossrequest,
	&ett_eobi3_quoterequest,
	&ett_eobi3_topofbook,
	&ett_eobi3_productsummary,
	&ett_eobi3_instrumentsummary,
	&ett_eobi3_snapshotorder,
    };

    proto_eobi3 = proto_register_protocol(
	"Eurex EOBI3 Protocol", /* name */
	"EOBI3",         /* short name */
	"eobi3"          /* abbrev */
	);

    proto_register_field_array(proto_eobi3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*
     * Register a preferences module (see section 2.6 of README.developer
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_PROTOABBREV in the following.
     */

    eobi3_module = prefs_register_protocol(proto_eobi3, proto_reg_handoff_eobi3);

    range_convert_str(&global_eobi3_udp_range, UDP_DEFAULT_RANGE, 65535);

    prefs_register_range_preference(
	eobi3_module,
	"udp.port",
	"UDP Ports",
	"UDP Ports range",
	&global_eobi3_udp_range, 65535);
}

void proto_reg_handoff_eobi3(void)
{
    eobi3_handle = create_dissector_handle(dissect_eobi3, proto_eobi3);
    // dissector_add_uint("udp.port", EOBI3_UDP_PORT, eobi3_handle);

    reinit_eobi3();
}
