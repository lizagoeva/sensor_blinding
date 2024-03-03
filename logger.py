import logging

LOG_INFO = logging.info
LOG_WARN = logging.warning
LOG_ERROR = logging.error
LOG_DEBUG = logging.debug

config_to_level = {
    "debug": 10,
    "info": 20,
    "warn": 30,
    "error": 40,
    "critical": 50
}


def configure_logging(log_file: str, log_level: str) -> int:
    try:
        logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            encoding="utf-8",
                            level=config_to_level[log_level.lower()],
                            filemode="w",
                            filename=log_file)
        return 0
    except Exception as error:
        return -1


def clog(msg: str, logger) -> int:
    print(msg)
    logger(msg)
    return 0
