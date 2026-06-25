from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp, echo


log = core.getLogger()

RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RESET  = "\033[0m"

def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")

PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK   = 24
PRIVATE_IP     = IPAddr("192.168.1.254")
PUBLIC_IP      = IPAddr("200.0.0.254")
PUBLIC_MAC     = EthAddr("00:00:00:aa:aa:aa")
PRIVATE_MAC    = EthAddr("00:00:00:bb:bb:bb")
PUBLIC_PORT    = 1                       # Puerto del switch hacia la red pública

NAT_PORT_MIN = 1024
NAT_PORT_MAX = 65535

FLOW_IDLE_TIMEOUT = 30   # segundos sin tráfico → el switch elimina el flujo
FLOW_HARD_TIMEOUT = 120  # segundos máximos de vida del flujo


class NATEntry:
    def __init__(self, proto, priv_ip, priv_port, pub_port, priv_mac, priv_switch_port):
        self.proto            = proto           # TCP / UDP
        self.priv_ip          = priv_ip         # host privado
        self.priv_port        = priv_port       # puerto original
        self.pub_port         = pub_port        # puerto asignado en la IP pública
        self.priv_mac         = priv_mac        # MAC del host privado
        self.priv_switch_port = priv_switch_port  # puerto del switch hacia el host


class ProtoRouter:
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # arp_table[ip] = (EthAddr, switch_port)
        self.arp_table: dict[IPAddr, tuple] = {}

        # pending_arp[ip] = [Paquetes esperando conocer la MAC destino, ...]
        self.pending_arp: dict[IPAddr, list] = {}

        # Tabla NAT: (proto, pub_port) → NATEntry
        self.nat_table: dict[tuple, NATEntry] = {}

        # Índice inverso rápido: (proto, priv_ip, priv_port) → pub_port
        self.nat_reverse: dict[tuple, int] = {}

        # Siguiente puerto NAT disponible
        self._next_nat_port = NAT_PORT_MIN

        # (priv_ip, icmp_id) → pub_id
        self.icmp_nat_out  = {}  

        # pub_id → (priv_ip, icmp_id, priv_mac, priv_switch_port)
        self.icmp_nat_in   = {}
        self._next_icmp_id = 1024


    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("PacketIn con trama no reconocida — descartado.")
            return

        ptype = event.parsed.type
        if ptype == ethernet.IP_TYPE:
            self.handle_ip(event)
        elif ptype == ethernet.ARP_TYPE:
            self.handle_arp(event)
        else:
            log_color(YELLOW, f"Protocolo 0x{ptype:04x} ignorado.")

    # Manejo IP

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        src_is_private = ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK)
        dst_is_private = ip_pkt.dstip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK)

        log_color(YELLOW,
            f"IP  {ip_pkt.srcip} → {ip_pkt.dstip}  "
            f"[{packet.src} → {packet.dst}]  port={in_port}")

        if src_is_private and dst_is_private:
            # Trafico interno
            self._handle_local(event, packet, ip_pkt, in_port)

        elif src_is_private and not dst_is_private:
            # Trafico saliente
            self._handle_outbound(event, packet, ip_pkt, in_port)

        elif not src_is_private and ip_pkt.dstip == PUBLIC_IP:
            # Paquete ICMP REPLY ENTRANTE
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
                self._handle_icmp_nat_in(event, packet, ip_pkt)

        elif not src_is_private and dst_is_private:
            # Trafico entrante (No permitido)
            log_color(RED, f"Paquete desde red pública hacia privada sin entrada NAT — descartado.")
        else:
            log_color(RED, f"Paquete entre redes públicas — descartado.")


    def _handle_local(self, event, packet, ip_pkt, in_port):
        dst_ip = ip_pkt.dstip

        if dst_ip == PRIVATE_IP:
            return

        if dst_ip not in self.arp_table:
            self._enqueue_and_arp(event, dst_ip)
            return

        dst_mac, dst_port = self.arp_table[dst_ip]

        self._install_local_flow(ip_pkt.srcip, ip_pkt.dstip, in_port, dst_port, dst_mac, packet.src)

        self._install_local_flow(ip_pkt.dstip, ip_pkt.srcip, dst_port, in_port, packet.src, dst_mac)

        # Enviar el paquete actual
        packet.src = PRIVATE_MAC
        packet.dst = dst_mac
        self._send_packet_out(packet.pack(), dst_port)
        log_color(GREEN, f"LOCAL  {ip_pkt.srcip} → {ip_pkt.dstip}  out_port={dst_port}")

    def _install_local_flow(self, src_ip, dst_ip, in_port, out_port, new_dst_mac, new_src_mac):
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_IDLE_TIMEOUT
        fm.hard_timeout = FLOW_HARD_TIMEOUT
        fm.match.dl_type  = 0x0800
        fm.match.nw_src   = src_ip
        fm.match.nw_dst   = dst_ip
        fm.match.in_port  = in_port
        fm.actions.append(of.ofp_action_dl_addr.set_src(new_src_mac))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(new_dst_mac))
        fm.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(fm)


    def _handle_outbound(self, event, packet, ip_pkt, in_port):
        # Solo soportamos TCP, ICMP Y UDP
        proto = ip_pkt.protocol

        if proto == ipv4.ICMP_PROTOCOL:
            self._handle_icmp_nat_out(event, packet, ip_pkt, in_port)
            return

        if proto not in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
            log_color(RED, f"Protocolo IP {proto} no soportado por NAT — descartado.")
            return

        l4 = ip_pkt.payload
        if l4 is None:
            return
        priv_port = l4.srcport
        dst_port  = l4.dstport

       
        nat_key_rev = (proto, ip_pkt.srcip, priv_port)
        if nat_key_rev in self.nat_reverse:
            pub_port = self.nat_reverse[nat_key_rev]
        else:
            pub_port = self._alloc_nat_port()
            entry = NATEntry(proto, ip_pkt.srcip, priv_port,
                             pub_port, packet.src, in_port)
            self.nat_table[(proto, pub_port)] = entry
            self.nat_reverse[nat_key_rev]     = pub_port
            log_color(GREEN,
                f"NAT NEW  {ip_pkt.srcip}:{priv_port} → {PUBLIC_IP}:{pub_port} "
                f"→ {ip_pkt.dstip}:{dst_port}  proto={proto}")

        entry = self.nat_table[(proto, pub_port)]

   
        if ip_pkt.dstip not in self.arp_table:
            self._enqueue_and_arp(event, ip_pkt.dstip)
            return

        dst_mac, _ = self.arp_table[ip_pkt.dstip]

        # Instalar flujos en el switch
        self._install_nat_out_flow(
            ip_pkt.srcip, priv_port, ip_pkt.dstip, dst_port,
            proto, in_port, pub_port, dst_mac)

        self._install_nat_in_flow(
            ip_pkt.dstip, dst_port, pub_port,
            proto, PUBLIC_PORT, entry)

        # Enviar paquete actual ya traducido
        self._forward_nat_outbound(packet, ip_pkt, l4, pub_port, dst_mac)

    def _install_nat_out_flow(self, src_ip, src_port, dst_ip, dst_port,
                                   proto, in_port, pub_port, dst_mac):
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_IDLE_TIMEOUT
        fm.hard_timeout = FLOW_HARD_TIMEOUT
        fm.match.dl_type   = 0x0800
        fm.match.nw_proto  = proto
        fm.match.nw_src    = src_ip
        fm.match.nw_dst    = dst_ip
        fm.match.in_port   = in_port
        if proto == ipv4.TCP_PROTOCOL:
            fm.match.tp_src = src_port
            fm.match.tp_dst = dst_port
        else:
            fm.match.tp_src = src_port
            fm.match.tp_dst = dst_port

        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm)

    def _install_nat_in_flow(self, pub_dst_ip, pub_dst_port, pub_port,
                                  proto, in_port, entry):
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_IDLE_TIMEOUT
        fm.hard_timeout = FLOW_HARD_TIMEOUT
        fm.match.dl_type   = 0x0800
        fm.match.nw_proto  = proto
        fm.match.nw_src    = pub_dst_ip
        fm.match.nw_dst    = PUBLIC_IP
        fm.match.in_port   = in_port
        fm.match.tp_src    = pub_dst_port
        fm.match.tp_dst    = pub_port

        fm.actions.append(of.ofp_action_nw_addr.set_dst(entry.priv_ip))
        fm.actions.append(of.ofp_action_tp_port.set_dst(entry.priv_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(entry.priv_mac))
        fm.actions.append(of.ofp_action_output(port=entry.priv_switch_port))
        self.connection.send(fm)

    def _forward_nat_outbound(self, packet, ip_pkt, l4, pub_port, dst_mac):
        # Reescribir L4
        l4.srcport = pub_port
        # Reescribir IP
        ip_pkt.srcip = PUBLIC_IP
        ip_pkt.payload = l4
        # Reescribir Ethernet
        packet.src = PUBLIC_MAC
        packet.dst = dst_mac
        self._send_packet_out(packet.pack(), PUBLIC_PORT)
        log_color(CYAN,
            f"NAT OUT  {PUBLIC_IP}:{pub_port} → {ip_pkt.dstip}  out_port={PUBLIC_PORT}")

    # Manejo ARP

    def handle_arp(self, event):
        packet  = event.parsed
        arp_pkt = packet.payload
        in_port = event.port

        log_color(YELLOW,
            f"ARP  op={'REQ' if arp_pkt.opcode == arp.REQUEST else 'REP'}  "
            f"{arp_pkt.protosrc} ({arp_pkt.hwsrc}) → {arp_pkt.protodst}")

        if arp_pkt.opcode == arp.REQUEST:
            self._handle_arp_request(event, arp_pkt, in_port)

        elif arp_pkt.opcode == arp.REPLY:
            self._handle_arp_reply(event, arp_pkt, in_port)

        else:
            log_color(RED, f"ARP opcode desconocido {arp_pkt.opcode} — descartado.")

    def _handle_arp_request(self, event, arp_pkt, in_port):
        target_ip = arp_pkt.protodst

        # Aprender al emisor
        self._learn_arp(arp_pkt.protosrc, arp_pkt.hwsrc, in_port)

        if target_ip == PRIVATE_IP:
            # Alguien pregunta por la IP privada del router
            self._send_arp_reply(event, arp_pkt.protosrc, arp_pkt.hwsrc,
                                 PRIVATE_MAC, PRIVATE_IP)

        elif target_ip == PUBLIC_IP:
            # Alguien pregunta por la IP pública del router
            self._send_arp_reply(event, arp_pkt.protosrc, arp_pkt.hwsrc,
                                 PUBLIC_MAC, PUBLIC_IP)

        elif target_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            # ARP interno: forwarding o broadcast
            if target_ip in self.arp_table:
                _, dst_port = self.arp_table[target_ip]
                self._send_arp_forward(event, arp_pkt, dst_port)
            else:
                self._flood_arp(event, arp_pkt)

        else:
            # Para red pública: el router actúa como proxy ARP
            self._send_arp_reply(event, arp_pkt.protosrc, arp_pkt.hwsrc,
                                 PUBLIC_MAC, target_ip)

    def _handle_arp_reply(self, event, arp_pkt, in_port):
        # Primero aprender, después procesar cola
        self._learn_arp(arp_pkt.protosrc, arp_pkt.hwsrc, in_port)

        # Procesar paquetes que estaban esperando esta MAC
        if arp_pkt.protosrc in self.pending_arp:
            pending = self.pending_arp.pop(arp_pkt.protosrc)
            log_color(GREEN,
                f"ARP resuelto {arp_pkt.protosrc} → {arp_pkt.hwsrc}. "
                f"Procesando {len(pending)} paquete(s) pendiente(s).")
            for e in pending:
                self.handle_ip(e)

        # Forwarding del reply si el destino es un host privado
        if arp_pkt.protodst.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            if arp_pkt.protodst in self.arp_table:
                _, dst_port = self.arp_table[arp_pkt.protodst]
                self._send_arp_forward(event, arp_pkt, dst_port)

    def _learn_arp(self, ip, mac, port):
        if ip not in self.arp_table:
            log_color(GREEN, f"ARP LEARN  {ip} → {mac}  port={port}")
        self.arp_table[ip] = (mac, port)

    # ── Helpers ARP ──────────────────────────────────────────────────────────

    def _send_arp_reply(self, event, dst_ip, dst_mac, src_mac, src_ip):
        reply = arp()
        reply.opcode  = arp.REPLY
        reply.hwsrc   = src_mac
        reply.protosrc = src_ip
        reply.hwdst   = dst_mac
        reply.protodst = dst_ip

        eth = ethernet()
        eth.type    = ethernet.ARP_TYPE
        eth.src     = src_mac
        eth.dst     = dst_mac
        eth.payload = reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(msg)
        log_color(CYAN, f"ARP REPLY  {src_ip} ({src_mac}) → {dst_ip} ({dst_mac})")

    def _send_arp_request(self, target_ip, src_mac, src_ip, out_port):
        req = arp()
        req.opcode   = arp.REQUEST
        req.hwsrc    = src_mac
        req.protosrc = src_ip
        req.hwdst    = EthAddr("00:00:00:00:00:00")
        req.protodst = target_ip

        eth = ethernet()
        eth.type    = ethernet.ARP_TYPE
        eth.src     = src_mac
        eth.dst     = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.payload = req

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        log_color(CYAN, f"ARP REQUEST  ¿Quién tiene {target_ip}? Pregunta {src_ip}")

    def _send_arp_forward(self, event, arp_pkt, out_port):
        eth = ethernet()
        eth.type    = ethernet.ARP_TYPE
        eth.src     = arp_pkt.hwsrc
        eth.dst     = arp_pkt.hwdst if arp_pkt.opcode == arp.REPLY else EthAddr("ff:ff:ff:ff:ff:ff")
        eth.payload = arp_pkt

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _flood_arp(self, event, arp_pkt):
        eth = ethernet()
        eth.type    = ethernet.ARP_TYPE
        eth.src     = arp_pkt.hwsrc
        eth.dst     = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.payload = arp_pkt

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _enqueue_and_arp(self, event, target_ip):
        first_request = target_ip not in self.pending_arp
        if first_request:
            self.pending_arp[target_ip] = []

        self.pending_arp[target_ip].append(event)

        if first_request:
            # Elegir desde qué interfaz preguntar
            if target_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
                self._send_arp_request(target_ip, PRIVATE_MAC, PRIVATE_IP, of.OFPP_FLOOD)
            else:
                self._send_arp_request(target_ip, PUBLIC_MAC, PUBLIC_IP, PUBLIC_PORT)


    def _send_packet_out(self, data, out_port):
        msg = of.ofp_packet_out()
        msg.data = data
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _alloc_nat_port(self):
        start = self._next_nat_port
        while True:
            port = self._next_nat_port
            self._next_nat_port += 1
            if self._next_nat_port > NAT_PORT_MAX:
                self._next_nat_port = NAT_PORT_MIN
            if (ipv4.TCP_PROTOCOL, port) not in self.nat_table and \
               (ipv4.UDP_PROTOCOL, port) not in self.nat_table:
                return port
            if self._next_nat_port == start:
                raise RuntimeError("NAT port pool exhausted!")

    def _handle_icmp_nat_out(self, event, packet, ip_pkt, in_port):
        icmp_pkt = ip_pkt.payload
        # Solo traducimos Echo Request (type=8)
        if icmp_pkt.type != 8: # 8 equivale a ECHO REQUEST
            return

        echo_pkt = icmp_pkt.payload
        priv_id  = echo_pkt.id

        key_out = (ip_pkt.srcip, priv_id)
        if key_out in self.icmp_nat_out:
            pub_id = self.icmp_nat_out[key_out]
        else:
            pub_id = self._next_icmp_id
            self._next_icmp_id += 1
            self.icmp_nat_out[key_out] = pub_id
            self.icmp_nat_in[pub_id]   = (ip_pkt.srcip, priv_id, packet.src, in_port)

        if ip_pkt.dstip not in self.arp_table:
            self._enqueue_and_arp(event, ip_pkt.dstip)
            return

        dst_mac, _ = self.arp_table[ip_pkt.dstip]

        # Reescribir manualmente y enviar (sin instalar flujo)
        echo_pkt.id    = pub_id
        icmp_pkt.payload = echo_pkt
        icmp_pkt.csum = 0          # POX recalcula al hacer .pack()
        ip_pkt.srcip   = PUBLIC_IP
        ip_pkt.payload = icmp_pkt
        ip_pkt.csum = 0
        packet.src     = PUBLIC_MAC
        packet.dst     = dst_mac

        self._send_packet_out(packet.pack(), PUBLIC_PORT)
        log_color(CYAN, f"ICMP NAT OUT  {key_out[0]} id={priv_id} → {PUBLIC_IP} id={pub_id}")

    def _handle_icmp_nat_in(self, event, packet, ip_pkt):
        icmp_pkt = ip_pkt.payload
        if icmp_pkt.type != 0: # 0 equivale a ECHO REPLY
            return

        echo_pkt = icmp_pkt.payload
        pub_id   = echo_pkt.id

        if pub_id not in self.icmp_nat_in:
            log_color(RED, f"ICMP NAT IN: no hay entrada para id={pub_id}")
            return

        priv_ip, priv_id, priv_mac, priv_port = self.icmp_nat_in[pub_id]

        echo_pkt.id      = priv_id
        icmp_pkt.payload = echo_pkt
        icmp_pkt.csum = 0
        ip_pkt.dstip     = priv_ip
        ip_pkt.payload   = icmp_pkt
        ip_pkt.csum  = 0
        packet.src       = PRIVATE_MAC
        packet.dst       = priv_mac

        self._send_packet_out(packet.pack(), priv_port)
        log_color(CYAN, f"ICMP NAT IN   id={pub_id} → {priv_ip} id={priv_id}")    

def launch():
    def start_switch(event):
        log_color(YELLOW, f"ProtoRouter iniciado para switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)