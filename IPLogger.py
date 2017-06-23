from datetime import datetime
import os.path
import pickle
import Server
import Packet
import Logger


class IPLogger(Server.Server):
    def __init__(self, list_file_path, *args, **kwargs):
        super(IPLogger, self).__init__(*args, **kwargs)
        self.list_file_path = list_file_path
        self.load_ip_list()

    def start(self, *args, **kwargs):
        self.logger.info("Started server for logging SoF2 clients IP")
        super(IPLogger, self).start(*args, **kwargs)

    def _get_info_handler(self, received_packet, address, *args, **kwargs):
        if address[0] == self.heartbeat_ip:
            super(IPLogger, self)._get_info_handler(received_packet, address, *args, **kwargs)
        self.logger.info("Caught {}:{}".format(address[0], address[1]))
        self.ip_list.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), address[0]))

    def load_ip_list(self):
        if not os.path.isfile(self.list_file_path):
            with open(self.list_file_path, "wb") as list_file:
                pickle.dump([], list_file, protocol=2)

        with open(self.list_file_path, "rb") as list_file:
            self.ip_list = pickle.load(list_file)

    def close(self, *args, **kwargs):
        with open(self.list_file_path, "wb") as list_file:
            pickle.dump(self.ip_list, list_file, protocol=2)

        super(IPLogger, self).close(*args, **kwargs)

def main():
    server = IPLogger("ip.pkl", "0.0.0.0", 20104, "104.40.23.123", 20110)
    Logger.MainLogger.log_to_file(datetime.now().strftime("Logs\\%Y_%m_%d_%H_%M_%S_IPLogger.log"))
    server.start()
    Logger.MainLogger.close()

if __name__ == "__main__":
    main()