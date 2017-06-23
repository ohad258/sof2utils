from datetime import datetime
import socket
import collections
import select
import threading
import time
import Packet
import Logger

MAX_UDP_PACKET_SIZE = 64000
HEARTBEAT_TIMER_INTERVAL = 550


class Server(Logger.LogMixin):
    def __init__(self, ip_address, port, heartbeat_ip="", heartbeat_port=0):
        # TODO: should be possible to go on without availiable heartbeat server
        self.port = port
        self.ip_address = ip_address
        self.server = None
        self.heartbeat_thread = None
        self.is_heartbeat_thread_on = False
        self.heartbeat_ip = heartbeat_ip
        self.heartbeat_port = heartbeat_port
        self.handlers = {Packet.TYPE_GET_STATUS: self._get_status_handler,
                         Packet.TYPE_GET_INFO: self._get_info_handler}
        self.info = collections.OrderedDict()
        self.status = collections.OrderedDict()

        if heartbeat_ip == "":
            self.is_local = True
        else:
            self.is_local = False


    def start(self):
        self._set_server_information()
        self._set_server_status()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((self.ip_address, self.port))
        self.logger.info("Started listening on {}:{}".format(self.ip_address, self.port))

        if self.is_local:
            self.logger.info("Server will be local")
        else:
            self.logger.info("Main master server was set to {}:{}".format(self.heartbeat_ip,
                                                                          self.heartbeat_port))
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_sender)
            self.heartbeat_thread.start()

        self._receiver()

    def _restart(self):
        self.server.close()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((self.ip_address, self.port))
        self.logger.info("Server has been restarted")

    def close(self):
        if not self.is_local:
            self._send_heartbeat_flatline()
        if self.server:
            self.server.close()
        self.is_heartbeat_thread_on = False

    def _set_server_status(self):
        self.status["game_version"] = "sof2mp-1.00"
        self.status["sv_keywords"] = "SOF2FULL "
        self.status["challenge"] = ""
        self.status["sv_floodProtect"] = "1"
        self.status["sv_maxPing"] = "0"
        self.status["sv_minPing"] = "0"
        self.status["sv_maxRate"] = "0"
        self.status["sv_hostname"] = "Jesus of Suburbia"
        self.status["dmflags"] = "8"
        self.status["timelimit"] = "20"
        self.status["sv_maxclients"] = "8"
        self.status["sv_allowDownload"] = "0"
        self.status["g_friendlyFire"] = "0"
        self.status["g_allowThirdPerson"] = "1"
        self.status["scorelimit"] = "0"
        self.status["g_maxGameClients"] = "0"
        self.status["version"] = "SOF2MP V1.00 win-x86 May  3 2002"
        self.status["fraglimit"] = "20"
        self.status["g_gametype"] = "inf"
        self.status["g_needpass"] = "0"
        self.status["protocol"] = "2002"
        self.status["mapname"] = "mp_shop"
        self.status["sv_privateClients"] = "0"
        self.status["sv_allowAnonymous"] = "0"
        self.status["sv_pure"] = "0"
        self.status["bot_minplayers"] = "0"
        self.status["^3Mod Name"] = "1fx. Mod"
        self.status["^3Mod Version"] = "0.81n.010"
        self.status["^3Mod Flavor"] = "pre+dev"
        self.status["^3Mod URL"] = "1fxmod.org"
        self.status["gamename"] = "sof2mp"
        self.status["g_availableWeapons"] = "200200002200000000000"
        self.status["current_gametype"] = "3"
        self.status["modname"] = "RPM 2 k 3 v2.00 ^_- ^31fxmod.org"

    def _set_server_information(self):
        self.info["sv_allowAnonymous"] = "0"
        self.info["game"] = "1fx"
        self.info["sv_allowDownload"] = "0"
        self.info["hostname"] = "Jesus of Suburbia"
        self.info["clients"] = "0"
        self.info["g_needpass"] = "0"
        self.info["pure"] = "0"
        self.info["gametype"] = "inf"
        self.info["sv_maxclients"] = "8"
        self.info["protocol"] = "2002"
        self.info["challenge"] = ""
        self.info["mapname"] = "mp_shop"

    def _heartbeat_sender(self):
        self.is_heartbeat_thread_on = True

        while self.is_heartbeat_thread_on:
            self._send_heartbeat()
            for second in range(0, HEARTBEAT_TIMER_INTERVAL):
                time.sleep(1)
                if not self.is_heartbeat_thread_on:
                    break

    def _receiver(self):
        while True:
            try:
                received_data, _, _ = select.select([self.server], [], [], 5)
                if not received_data:
                    continue

                received_buffer, address = self.server.recvfrom(MAX_UDP_PACKET_SIZE)
                unpacked_buffer = Packet.unpack(received_buffer)
                self._packet_handler(unpacked_buffer, address)

            except KeyboardInterrupt:
                self.logger.error("KeyboardInterrupt")
                self.close()
                break

            except socket.error, e:
                self.logger.error(e)
                self._restart()

            except Exception, e:
                self.logger.error(e)
                self.close()

    def _packet_handler(self, packet, address):
        self.logger.info("{}:{} has sent \"{}\"".format(address[0], address[1], packet.id))

        if packet.id[-1] == "\x00":
            packet.id = packet.id[:-1]
        if packet.id in self.handlers.keys():
            self.handlers[packet.id](packet, address)
        else:
            self.logger.error("Handler for \"{}\" does not exist".format(packet.id))

    def _send_heartbeat(self):
        packet = Packet.Packet()
        packet.id = Packet.TYPE_HEARTBEAT
        packet.id_parameter = "SoF2MP-1"
        self._send(packet, (self.heartbeat_ip, self.heartbeat_port))
        self.logger.info("Sent heartbeat")

    def _send_heartbeat_flatline(self):
        packet = Packet.Packet()
        packet.id = Packet.TYPE_HEARTBEAT
        packet.id_parameter = "flatline SoF2MP-1"
        self._send(packet, (self.heartbeat_ip, self.heartbeat_port))
        self.logger.info("Sent heartbeat flatline")

    def _send_version(self, address):
        packet = Packet.Packet()
        packet.id = Packet.TYPE_VERSION
        packet.id_parameter = "1.00"
        self.server.sendto(Packet.pack(packet)[:-1], (self.heartbeat_ip, self.heartbeat_port))
        self.logger.info("Sent version")

    def _get_info_handler(self, received_packet, address):
        packet = Packet.Packet()
        packet.id = Packet.TYPE_INFO_RESPONSE
        packet.info = self.info
        challenge = received_packet.id_parameter
        if challenge == "xxx":
            packet.info["challenge"] = challenge
        else:
            packet.info["challenge"] = challenge[:-1]

        self._send(packet, address)
        self.logger.info("Sent info with challenge {}".format(packet.info["challenge"]))

    def _get_status_handler(self, received_packet, address):
        packet = Packet.Packet()
        packet.id = Packet.TYPE_STATUS_RESPONSE
        packet.info = self.status
        challenge = received_packet.id_parameter
        if challenge == "xxx":
            packet.info["challenge"] = challenge
        else:
            packet.info["challenge"] = challenge[:-1]

        self._send(packet, address)
        self.logger.info("Sent status with challenge {}".format(packet.info["challenge"]))
        #a = "\xff\xff\xff\xff\x73\x74\x61\x74\x75\x73\x52\x65\x73\x70\x6f\x6e\x73\x65\x0a\x5c\x67\x61\x6d\x65\x5f\x76\x65\x72\x73\x69\x6f\x6e\x5c\x73\x6f\x66\x32\x6d\x70\x2d\x31\x2e\x30\x30\x5c\x73\x76\x5f\x6b\x65\x79\x77\x6f\x72\x64\x73\x5c\x53\x4f\x46\x32\x46\x55\x4c\x4c\x20\x5c\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x5c\x34\x37\x32\x31\x33\x36\x38\x35\x39\x5c\x67\x5f\x6d\x61\x78\x47\x61\x6d\x65\x43\x6c\x69\x65\x6e\x74\x73\x5c\x30\x5c\x73\x63\x6f\x72\x65\x6c\x69\x6d\x69\x74\x5c\x30\x5c\x67\x5f\x61\x6c\x6c\x6f\x77\x54\x68\x69\x72\x64\x50\x65\x72\x73\x6f\x6e\x5c\x31\x5c\x67\x5f\x66\x72\x69\x65\x6e\x64\x6c\x79\x46\x69\x72\x65\x5c\x30\x5c\x73\x76\x5f\x61\x6c\x6c\x6f\x77\x44\x6f\x77\x6e\x6c\x6f\x61\x64\x5c\x30\x5c\x73\x76\x5f\x6d\x61\x78\x63\x6c\x69\x65\x6e\x74\x73\x5c\x38\x5c\x74\x69\x6d\x65\x6c\x69\x6d\x69\x74\x5c\x32\x30\x5c\x64\x6d\x66\x6c\x61\x67\x73\x5c\x38\x5c\x73\x76\x5f\x68\x6f\x73\x74\x6e\x61\x6d\x65\x5c\x31\x66\x78\x2e\x20\x50\x6f\x77\x65\x72\x65\x64\x5c\x73\x76\x5f\x6d\x61\x78\x52\x61\x74\x65\x5c\x30\x5c\x73\x76\x5f\x6d\x69\x6e\x50\x69\x6e\x67\x5c\x30\x5c\x73\x76\x5f\x6d\x61\x78\x50\x69\x6e\x67\x5c\x30\x5c\x73\x76\x5f\x66\x6c\x6f\x6f\x64\x50\x72\x6f\x74\x65\x63\x74\x5c\x31\x5c\x76\x65\x72\x73\x69\x6f\x6e\x5c\x53\x4f\x46\x32\x4d\x50\x20\x56\x31\x2e\x30\x30\x20\x77\x69\x6e\x2d\x78\x38\x36\x20\x4d\x61\x79\x20\x20\x33\x20\x32\x30\x30\x32\x5c\x66\x72\x61\x67\x6c\x69\x6d\x69\x74\x5c\x32\x30\x5c\x67\x5f\x67\x61\x6d\x65\x74\x79\x70\x65\x5c\x69\x6e\x66\x5c\x67\x5f\x6e\x65\x65\x64\x70\x61\x73\x73\x5c\x30\x5c\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x5c\x32\x30\x30\x32\x5c\x6d\x61\x70\x6e\x61\x6d\x65\x5c\x6d\x70\x5f\x73\x68\x6f\x70\x5c\x73\x76\x5f\x70\x72\x69\x76\x61\x74\x65\x43\x6c\x69\x65\x6e\x74\x73\x5c\x30\x5c\x73\x76\x5f\x61\x6c\x6c\x6f\x77\x41\x6e\x6f\x6e\x79\x6d\x6f\x75\x73\x5c\x30\x5c\x73\x76\x5f\x70\x75\x72\x65\x5c\x30\x5c\x62\x6f\x74\x5f\x6d\x69\x6e\x70\x6c\x61\x79\x65\x72\x73\x5c\x30\x5c\x5e\x33\x4d\x6f\x64\x20\x4e\x61\x6d\x65\x5c\x31\x66\x78\x2e\x20\x4d\x6f\x64\x5c\x5e\x33\x4d\x6f\x64\x20\x56\x65\x72\x73\x69\x6f\x6e\x5c\x30\x2e\x38\x31\x6e\x2e\x30\x31\x30\x5c\x5e\x33\x4d\x6f\x64\x20\x46\x6c\x61\x76\x6f\x72\x5c\x70\x72\x65\x2b\x64\x65\x76\x5c\x5e\x33\x4d\x6f\x64\x20\x55\x52\x4c\x5c\x31\x66\x78\x6d\x6f\x64\x2e\x6f\x72\x67\x5c\x67\x61\x6d\x65\x6e\x61\x6d\x65\x5c\x73\x6f\x66\x32\x6d\x70\x5c\x67\x5f\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x57\x65\x61\x70\x6f\x6e\x73\x5c\x32\x30\x30\x32\x30\x30\x30\x30\x32\x32\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x5c\x63\x75\x72\x72\x65\x6e\x74\x5f\x67\x61\x6d\x65\x74\x79\x70\x65\x5c\x33\x5c\x6d\x6f\x64\x6e\x61\x6d\x65\x5c\x52\x50\x4d\x20\x32\x20\x6b\x20\x33\x20\x76\x32\x2e\x30\x30\x20\x5e\x5f\x2d\x20\x5e\x33\x31\x66\x78\x6d\x6f\x64\x2e\x6f\x72\x67\x0a"
        #self.server.sendto(a, address)

        if address[0] == self.heartbeat_ip:
            self._send_version(address)

    def _send(self, packet, to):
        self.server.sendto(Packet.pack(packet), to)


def main():
    Logger.MainLogger.log_to_file(datetime.now().strftime("Logs\\%Y_%m_%d_%H_%M_%S.log"))
    server = Server("0.0.0.0", 20102, "104.40.23.123", 20110)
    server.start()
    Logger.MainLogger.close()

if __name__ == "__main__":
    main()