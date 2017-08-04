from datetime import datetime
import csv
import os.path
import pickle
import Server
import Packet
import Logger
import FairplayRequester


class IPLogger(Server.Server):
    def __init__(self, list_file_path, resolved_file_path, resolved_csv_path, *args, **kwargs):
        super(IPLogger, self).__init__(*args, **kwargs)
        self.list_file_path = list_file_path
        self.resolved_file_path = resolved_file_path
        self.resolved_csv_path = resolved_csv_path
        self.ip_list = self.load_pickle_file(self.list_file_path, [])
        self.resolved_list = self.load_pickle_file(self.resolved_file_path, {})

    def start(self, *args, **kwargs):
        self.logger.info("Started server for logging SoF2 clients IP")
        super(IPLogger, self).start(*args, **kwargs)

    def _get_info_handler(self, received_packet, address, *args, **kwargs):
        if address[0] == self.heartbeat_ip:
            super(IPLogger, self)._get_info_handler(received_packet, address, *args, **kwargs)
        self.logger.info("Caught {}:{}".format(address[0], address[1]))
        self.ip_list.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), address[0]))

        if address[0] not in self.resolved_list.keys():
            self.resolved_list[address[0]] = {"guid": "", "fairshots": ""}
            response = FairplayRequester.request_by_ip(address[0])
            if response is not None:
                self.resolved_list[address[0]] = response
                self.logger.info("Resolved {} with the guid {}".format(address[0], response["guid"]))

    def load_pickle_file(self, path, base_content):
        if not os.path.isfile(path):
            with open(path, "wb") as created_file:
                pickle.dump(base_content, created_file, protocol=2)

        with open(path, "rb") as pickle_file:
            data = pickle.load(pickle_file)
        return data

    def close(self, *args, **kwargs):
        self._save_resolved_csv(self.resolved_csv_path)

        with open(self.list_file_path, "wb") as list_file:
            pickle.dump(self.ip_list, list_file, protocol=2)
        with open(self.resolved_file_path, "wb") as list_file:
            pickle.dump(self.resolved_list, list_file, protocol=2)

        super(IPLogger, self).close(*args, **kwargs)

    def _save_resolved_csv(self, path):
        with open(path, "w") as csvfile:
            field_names = ["IP", "GUID", "Fairshots"]
            writer = csv.DictWriter(csvfile, fieldnames=field_names)

            writer.writeheader()
            for key in self.resolved_list.iterkeys():
                writer.writerow({"IP": key, "GUID": self.resolved_list[key]["guid"], "Fairshots": self.resolved_list[key]["fairshots"]})

def main():
    server = IPLogger("ip.pkl", "resolved.pkl", "resolved.csv", "0.0.0.0", 20104, "104.40.23.123", 20110)
    Logger.MainLogger.log_to_file(datetime.now().strftime("Logs\\%Y_%m_%d_%H_%M_%S_IPLogger.log"))
    server.start()
    Logger.MainLogger.close()

if __name__ == "__main__":
    main()