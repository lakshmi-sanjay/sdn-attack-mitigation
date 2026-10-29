import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from filelock import FileLock
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet
from os_ken.ofproto import ofproto_v1_3

from sdn_defense import paths


PROJECT_DIR = paths.RUNTIME_DIR
REQUEST_FILE = paths.REQUEST_FILE
REQUEST_LOCK = FileLock(str(paths.REQUEST_LOCK_FILE))

EVENT_FILE = paths.BLOCK_EVENTS_FILE
EVENT_LOCK = FileLock(str(paths.BLOCK_EVENTS_LOCK_FILE))
CONTEXT_FILE = paths.CONTEXT_FILE

EVENT_COLUMNS = [
    "run_id",
    "condition",
    "scenario",
    "trial",
    "source_ip",
    "event",
    "epoch_time",
]


def get_experiment_context():
    """Read metadata for the current experiment trial."""
    defaults = {
        "run_id": "unassigned",
        "condition": "unknown",
        "scenario": "unknown",
        "trial": 0,
    }

    try:
        context = json.loads(CONTEXT_FILE.read_text())
        if isinstance(context, dict):
            defaults.update({
                key: context[key]
                for key in defaults
                if key in context
            })
    except (OSError, json.JSONDecodeError):
        pass

    return defaults


def log_block_event(source_ip, event):
    """Append an event with the required experiment CSV columns."""
    context = get_experiment_context()

    row = [
        context["run_id"],
        context["condition"],
        context["scenario"],
        context["trial"],
        str(source_ip),
        event,
        f"{time.time():.6f}",
    ]

    PROJECT_DIR.mkdir(parents=True, exist_ok=True)

    with EVENT_LOCK:
        file_exists = EVENT_FILE.exists() and EVENT_FILE.stat().st_size > 0

        with EVENT_FILE.open("a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            if not file_exists:
                writer.writerow(EVENT_COLUMNS)

            writer.writerow(row)


class LearningSwitch(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    BLOCK_TIMEOUT = 30
    BLOCK_PRIORITY = 100

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        # DROP rules whose presence has been confirmed by flow statistics.
        self.active_blocks = set()

        # IPs awaiting confirmation from a flow-statistics reply.
        self.pending_blocks = {}

        self.request_file = REQUEST_FILE
        self.request_lock = REQUEST_LOCK

        self.request_worker = hub.spawn(self.request_loop)

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER,
    )
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Send unmatched packets to the controller.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch connected: %s", datapath.id)

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        hard_timeout=0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]

        flags = 0

        # Ask the switch to notify us when a timed DROP rule is removed.
        if priority == self.BLOCK_PRIORITY and hard_timeout > 0:
            flags = ofproto.OFPFF_SEND_FLOW_REM

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout,
            flags=flags,
        )

        datapath.send_msg(mod)

    def request_flow_stats(self, datapath, ip_address):
        """Ask the switch for flow statistics to confirm installation."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.pending_blocks.setdefault(datapath.id, set()).add(
            ip_address
        )

        request = parser.OFPFlowStatsRequest(
            datapath=datapath,
            flags=0,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0,
            cookie_mask=0,
            match=parser.OFPMatch(),
        )

        datapath.send_msg(request)

    def block_ip(self, datapath, ip_address):
        """Install a 30-second DROP rule for an IPv4 source."""
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_address,
        )

        self.add_flow(
            datapath,
            priority=self.BLOCK_PRIORITY,
            match=match,
            actions=[],
            hard_timeout=self.BLOCK_TIMEOUT,
        )

        # Do not log drop_installed here. A FlowMod being sent is
        # not proof that the switch has installed the rule.
        self.request_flow_stats(datapath, ip_address)

        self.logger.info(
            "Sent DROP rule for %s; awaiting switch confirmation",
            ip_address,
        )

    def unblock_ip(self, datapath, ip_address):
        """Delete the priority-100 DROP rule for a source IP."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_address,
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            priority=self.BLOCK_PRIORITY,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )

        datapath.send_msg(mod)

        self.logger.info(
            "Sent DROP-rule deletion for %s",
            ip_address,
        )

    def process_block_requests(self):
        """Process queued block and unblock requests."""
        if not self.request_file.exists():
            return

        with self.request_lock:
            try:
                requests_list = json.loads(
                    self.request_file.read_text()
                )
            except (json.JSONDecodeError, OSError):
                self.logger.exception(
                    "Could not read block request queue"
                )
                return

            if not isinstance(requests_list, list):
                self.logger.error(
                    "Block request queue must contain a JSON list"
                )
                return

            self.request_file.write_text("[]")

        for item in requests_list:
            if not isinstance(item, dict):
                self.logger.warning(
                    "Ignoring malformed request: %r", item
                )
                continue

            action = item.get("action")
            ip_address = item.get("ip")

            if action not in ("block", "unblock"):
                self.logger.warning(
                    "Ignoring unknown request action: %r", action
                )
                continue

            if not isinstance(ip_address, str):
                self.logger.warning(
                    "Ignoring request with invalid IP: %r", item
                )
                continue

            for datapath in list(self.datapaths.values()):
                if action == "block":
                    self.block_ip(datapath, ip_address)
                else:
                    self.unblock_ip(datapath, ip_address)

    def request_loop(self):
        """Check the request queue periodically."""
        while True:
            try:
                self.process_block_requests()
            except Exception:
                self.logger.exception(
                    "Error processing block requests"
                )

            hub.sleep(1)

    def is_confirmed_drop(self, flow, ip_address):
        """Check that a reported flow is the intended DROP rule."""
        if flow.priority != self.BLOCK_PRIORITY:
            return False

        match = flow.match

        if str(match.get("ipv4_src", "")) != ip_address:
            return False

        if match.get("eth_type") != 0x0800:
            return False

        # A DROP flow has no output/apply actions.
        for instruction in flow.instructions:
            actions = getattr(instruction, "actions", None)

            if actions:
                return False

        return True

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER,
    )
    def flow_stats_reply_handler(self, ev):
        """Log installation only after the switch reports the DROP flow."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        pending = self.pending_blocks.get(dpid, set())
        if not pending:
            return

        confirmed_ips = set()

        for flow in msg.body:
            for ip_address in pending:
                if self.is_confirmed_drop(flow, ip_address):
                    confirmed_ips.add(ip_address)

        for ip_address in confirmed_ips:
            key = (dpid, ip_address)

            if key not in self.active_blocks:
                self.active_blocks.add(key)
                log_block_event(ip_address, "drop_installed")

                self.logger.info(
                    "Confirmed DROP rule installed: %s on switch %s",
                    ip_address,
                    dpid,
                )

        # A multipart statistics response may arrive in several pieces.
        more = bool(
            msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE
        )

        if not more:
            self.pending_blocks.pop(dpid, None)

            # A missing rule is not reported as installed.
            for ip_address in pending - confirmed_ips:
                self.logger.warning(
                    "DROP rule not confirmed for %s on switch %s",
                    ip_address,
                    dpid,
                )

    @set_ev_cls(
        ofp_event.EventOFPFlowRemoved,
        MAIN_DISPATCHER,
    )
    def flow_removed_handler(self, ev):
        """Record expiration or deletion of a confirmed DROP rule."""
        msg = ev.msg
        datapath = msg.datapath

        if msg.priority != self.BLOCK_PRIORITY:
            return

        ip_address = str(msg.match.get("ipv4_src", ""))

        if not ip_address:
            return

        key = (datapath.id, ip_address)

        # Ignore removals for rules we never confirmed as installed.
        if key not in self.active_blocks:
            return

        self.active_blocks.discard(key)

        log_block_event(ip_address, "block_removed")

        self.logger.info(
            "Confirmed DROP rule removed: %s on switch %s (reason=%s)",
            ip_address,
            datapath.id,
            msg.reason,
        )

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER,
    )
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None or eth.ethertype == 0x88CC:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(
            eth.dst,
            ofproto.OFPP_FLOOD,
        )

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=eth.src,
                eth_dst=eth.dst,
            )

            self.add_flow(
                datapath,
                priority=1,
                match=match,
                actions=actions,
            )

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )

        datapath.send_msg(out)
