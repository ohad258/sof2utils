import logging
import sys


class LogMixin(object):
    @property
    def logger(self):
        return MainLogger 


class Logger(logging.Logger):
    def __init__(self, *args, **kwargs):
        super(Logger, self).__init__(*args, **kwargs)

        self.formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", 
                                           datefmt="%Y-%m-%d %H:%M:%S")

        stdout = logging.StreamHandler(sys.stdout)
        stdout.setFormatter(self.formatter)
        self.addHandler(stdout)

    def log_to_file(self, log_file_path):
        log_file = logging.FileHandler(log_file_path)
        log_file.setFormatter(self.formatter)
        self.addHandler(log_file)

    def close(self):
        handlers = self.handlers[:]
        for handler in handlers:
            handler.close()
            self.removeHandler(handler)


MainLogger = Logger("MainLogger")