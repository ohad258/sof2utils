import struct

TYPE_HEARTBEAT = "heartbeat"
TYPE_GET_INFO = "getinfo"
TYPE_GET_STATUS = "getstatus"
TYPE_STATUS_RESPONSE = "statusResponse"
TYPE_INFO_RESPONSE = "infoResponse"
TYPE_VERSION = "version"
_BARKER = "\xFF\xFF\xFF\xFF"
SPLITTER = "\n"
INFO_SPLITTER = "\\"


class Packet():
    def __init__(self):
        self.id = ""
        self.id_parameter = ""
        self.info = {}

    def __str__(self):
        return self.id


def pack(packet):
    buff = "{}{}".format(_BARKER, packet.id)
    if packet.id_parameter:
        buff += " {}".format(packet.id_parameter)
    buff += SPLITTER

    for info_key in packet.info.iterkeys():
        buff += "{0}{1}{0}{2}".format(INFO_SPLITTER, info_key, packet.info[info_key])
    if packet.info:
        buff += "\n"

    return buff

def unpack(buff):
    packet = Packet()
    splitted_buffer = buff.split("\n")
    splitted_id = splitted_buffer[0].split(" ")
    # TODO: Im not validating here the FF barker
    packet.id = splitted_id[0][4:]
    if len(splitted_id) > 1:
        packet.id_parameter = splitted_id[1]
    return packet