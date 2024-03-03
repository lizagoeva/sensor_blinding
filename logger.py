import logging

LOGFILE = "./logs/run.log"

LOG_INFO = logging.info
LOG_WARN = logging.warning
LOG_ERROR = logging.error
LOG_DEBUG = logging.debug


def configure_logging() -> int:
    try:
        logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            encoding="utf-8",
                            level=logging.INFO,
                            filemode="w",
                            filename=LOGFILE)
        return 0
    except Exception as error:
        return -1


def clog(msg: str, logger) -> int:
    print(msg)
    logger(msg)
    return 0
