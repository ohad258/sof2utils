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