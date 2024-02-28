import logging

logging.basicConfig(level=logging.INFO, filename="py_log.log",filemode="w",format="%(asctime)s %(levelname)s %(message)s")

# logging.debug("A DEBUG Message")
# logging.info("An INFO")
# logging.warning("A WARNING")
# logging.error("An ERROR")
# logging.critical("A CRITICAL message")

mylogger = logging.getLogger('py_log')
mylogger.setLevel(logging.INFO)

def parser_logger(total_parsed_cnt, total_filtered_cnt):
    mylogger.info(f"Total parced packets count: {total_parsed_cnt}. Total filtered packets: {total_filtered_cnt}.")
    
def generator_logger():
    print('ok')