/* packet-udp-bttracker.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_BUILD_DLL

#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_attributes.h>
#include <ws_symbol_export.h>
#include <ws_version.h>

#ifndef VERSION
#define VERSION "0.0.1"
#endif

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

#define PROTO_NAME "Bittorrent Tracker over UDP"

typedef enum {
    ProtoMsgConnectRequest,
    ProtoMsgConnectResponse,
    ProtoMsgAnnounceRequest,
    ProtoMsgAnnounceResponse,
    ProtoMsgUnknown
} ProtoMsgType;

#define BT_UDP_CONNECT_REQ_LEN 16
#define BT_UDP_CONNECT_RESP_LEN 16
#define BT_UDP_ANNOUNCE_REQ_LEN 98
#define BT_UDP_ANNOUNCE_RESP_MIN_LEN 20

#define BT_UDP_CONNECT_REQ_MAGIC 0x41727101980UL

#define BT_UDP_CONNECT_ACTION 0
#define BT_UDP_ANNOUNCE_ACTION 1

static int hf_bt_udp_tracker_proto_id = -1;
static int hf_bt_udp_tracker_action = -1;
static int hf_bt_udp_tracker_txid = -1;
static int hf_bt_udp_tracker_conn_id = -1;
static int hf_bt_udp_tracker_info_hash = -1;
static int hf_bt_udp_tracker_peer_id = -1;
static int hf_bt_udp_tracker_downloaded = -1;
static int hf_bt_udp_tracker_left = -1;
static int hf_bt_udp_tracker_uploaded = -1;
static int hf_bt_udp_tracker_event = -1;
static int hf_bt_udp_tracker_leechers = -1;
static int hf_bt_udp_tracker_seeders = -1;
static int hf_bt_udp_tracker_interval = -1;
static int hf_bt_udp_tracker_ipv4 = -1;
static int hf_bt_udp_tracker_port = -1;
static int hf_bt_udp_tracker_peer_list = -1;
static int hf_bt_udp_tracker_peer = -1;
static int hf_bt_udp_tracker_key = -1;
static int hf_bt_udp_tracker_numwant = -1;

static gint ett_bt_udp_tracker = -1;
static gint ett_bt_udp_tracker_peer_list = -1;
static gint ett_bt_udp_tracker_peer = -1;
static int proto_udp_bttracker = -1;
static dissector_handle_t udp_bttracker_handle;

static const value_string action_names[] = {
    { BT_UDP_CONNECT_ACTION, "Connect" },
    { BT_UDP_ANNOUNCE_ACTION, "Announce" },
    { -1, NULL }
};

static const value_string event_names[] = {
    { 0, "None" },
    { 1, "Completed" },
    { 2, "Started" },
    { 3, "Stopped" },
    { -1, NULL }
};

static void
dissect_connect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;


    proto_tree_add_item(tree, hf_bt_udp_tracker_proto_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_udp_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_txid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
}

static void
dissect_connect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;

    proto_tree_add_item(tree, hf_bt_udp_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_txid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_conn_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
}

static void
dissect_announce_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;

    proto_tree_add_item(tree, hf_bt_udp_tracker_conn_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_udp_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_txid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_info_hash, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_item(tree, hf_bt_udp_tracker_peer_id, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_item(tree, hf_bt_udp_tracker_downloaded, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_udp_tracker_left, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_udp_tracker_uploaded, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_udp_tracker_event, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_key, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_numwant, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
}

static void
dissect_announce_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;

    proto_tree_add_item(tree, hf_bt_udp_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_txid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_leechers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_udp_tracker_seeders, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree *peer_list_item = proto_tree_add_item(tree, hf_bt_udp_tracker_peer_list, tvb, offset, -1, ENC_NA);
    proto_tree *peer_list_subtree = proto_item_add_subtree(peer_list_item, ett_bt_udp_tracker_peer_list);

    while (tvb_reported_length_remaining(tvb, offset) >= 6) 
    {
        proto_tree *peer_item = proto_tree_add_item(peer_list_subtree, hf_bt_udp_tracker_peer, tvb, offset, -1, ENC_NA);
        proto_tree *peer_subtree = proto_item_add_subtree(peer_item, ett_bt_udp_tracker_peer);

        proto_tree_add_item(peer_subtree, hf_bt_udp_tracker_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(peer_subtree, hf_bt_udp_tracker_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
}

static ProtoMsgType
determine_message_type(tvbuff_t *tvb)
{
    gint len = tvb_reported_length_remaining(tvb, 0);
    if (len == BT_UDP_CONNECT_REQ_LEN) {
        guint64 magic = tvb_get_guint64(tvb, 0, ENC_BIG_ENDIAN);
        // connect request
        if (magic == BT_UDP_CONNECT_REQ_MAGIC && tvb_get_guint32(tvb, 8, ENC_BIG_ENDIAN) == 0)
            return ProtoMsgConnectRequest;
        
        guint32 action = tvb_get_guint32(tvb, 0, ENC_BIG_ENDIAN);

        // connect response
        if (action == BT_UDP_CONNECT_ACTION)
            return ProtoMsgConnectResponse;
    } else if (len == BT_UDP_ANNOUNCE_REQ_LEN) {
        guint32 action = tvb_get_guint32(tvb, 8, ENC_BIG_ENDIAN);
        if (action == BT_UDP_ANNOUNCE_ACTION)
            return ProtoMsgAnnounceRequest;
    } else if (len >= BT_UDP_ANNOUNCE_RESP_MIN_LEN && (len - BT_UDP_ANNOUNCE_RESP_MIN_LEN) % 6 == 0) {
        guint32 action = tvb_get_guint32(tvb, 0, ENC_BIG_ENDIAN);

        if (action == BT_UDP_ANNOUNCE_ACTION)
            return ProtoMsgAnnounceResponse;
    }

    return ProtoMsgUnknown;
}

static int
dissect_bt_udp_tracker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ProtoMsgType msg_type;

    if (data != NULL) {
        msg_type = *((ProtoMsgType *) data);
    } else {
        msg_type = determine_message_type(tvb);
    }

    if (msg_type == ProtoMsgUnknown)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bittorrent UDP tracker");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    proto_item *ti = proto_tree_add_item(tree, proto_udp_bttracker, tvb, 0, -1, ENC_NA);
    proto_tree *packet_tree = proto_item_add_subtree(ti, ett_bt_udp_tracker);
    switch (msg_type)
    {
    case ProtoMsgConnectRequest:
        dissect_connect_request(tvb, pinfo, packet_tree);
        break;
    case ProtoMsgConnectResponse:
        dissect_connect_response(tvb, pinfo, packet_tree);
        break;
    case ProtoMsgAnnounceRequest:
        dissect_announce_request(tvb, pinfo, packet_tree);
        break;
    case ProtoMsgAnnounceResponse:
        dissect_announce_response(tvb, pinfo, packet_tree);
        break;
    default:
        return 0;
    }

    return tvb_captured_length(tvb);
}

static gboolean
dissect_bt_udp_tracker_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    ProtoMsgType msg_type = determine_message_type(tvb);
    if (msg_type == ProtoMsgUnknown) {
        return FALSE;
    }

    dissect_bt_udp_tracker(tvb, pinfo, tree, &msg_type);
    return TRUE;
}

static void
proto_register_bt_udp_tracker(void)
{

    static hf_register_info hf[] = {
        { &hf_bt_udp_tracker_proto_id,
            { "Protocol ID", "bt_udp_tracker.protocol_id",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_action,
            { "action", "bt_udp_tracker.action",
            FT_UINT32, BASE_DEC,
            VALS(action_names), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_txid,
            { "Transaction ID", "bt_udp_tracker.tx_id",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_conn_id,
            { "Connection ID", "bt_udp_tracker.conn_id",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_info_hash,
            { "Info Hash", "bt_udp_tracker.info_hash",
            FT_BYTES, SEP_SPACE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_peer_id,
            { "Peer ID", "bt_udp_tracker.peer_id",
            FT_BYTES, SEP_SPACE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_downloaded,
            { "Downloaded", "bt_udp_tracker.downloaded",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_left,
            { "Left", "bt_udp_tracker.left",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_uploaded,
            { "Uploaded", "bt_udp_tracker.uploaded",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_event,
            { "Event", "bt_udp_tracker.event",
            FT_UINT32, BASE_DEC,
            VALS(event_names), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_interval,
            { "Interval", "bt_udp_tracker.interval",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_leechers,
            { "Leechers", "bt_udp_tracker.leechers",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_seeders,
            { "Seeders", "bt_udp_tracker.seeders",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_ipv4,
            { "IPv4 address", "bt_udp_tracker.ipv4",
            FT_IPv4, BASE_NETMASK,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_port,
            { "Port", "bt_udp_tracker.port",
            FT_UINT16, BASE_PT_TCP,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_peer_list,
            { "Peer List", "bt_udp_tracker.peer_list",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_peer,
            { "Peer", "bt_udp_tracker.peer",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_key,
            { "Key", "bt_udp_tracker.key",
            FT_BYTES, SEP_SPACE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_udp_tracker_numwant,
            { "Peer", "bt_udp_tracker.numwant",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };
    static gint *ett[] = {
        &ett_bt_udp_tracker,
        &ett_bt_udp_tracker_peer_list,
        &ett_bt_udp_tracker_peer
    };

    proto_udp_bttracker = proto_register_protocol(PROTO_NAME, "BT UDP Tracker", "bt_udp_tracker");

    proto_register_field_array(proto_udp_bttracker, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void
proto_reg_handoff_bt_udp_tracker(void)
{
    udp_bttracker_handle = create_dissector_handle(dissect_bt_udp_tracker, proto_udp_bttracker);

    heur_dissector_add("udp", dissect_bt_udp_tracker_heur, "Bittorrent UDP Tracker", "bt_udp_tracker", proto_udp_bttracker, HEURISTIC_DISABLE);

    dissector_add_for_decode_as_with_preference("udp.port", udp_bttracker_handle);
}

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_bt_udp_tracker;
    plug.register_handoff = proto_reg_handoff_bt_udp_tracker;
    proto_register_plugin(&plug);
}
