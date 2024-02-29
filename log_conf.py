import logging

logging.basicConfig(level=logging.INFO, filename="py_log.log",filemode="a",format="%(asctime)s %(levelname)s %(message)s")

# logging.debug("A DEBUG Message")
# logging.info("An INFO")
# logging.warning("A WARNING")
# logging.error("An ERROR")
# logging.critical("A CRITICAL message")

mylogger = logging.getLogger('py_log')
mylogger.setLevel(logging.INFO)

def parser_logger(logs):
    rules_file, protocol, host, port, total_parsed_cnt, total_filtered_cnt = logs.values()
    mylogger.info(f"Current filter settings (file, protocol, host, port): {rules_file}, {protocol}, {host}, {port}")
    mylogger.info(f"Total parced packets count: {total_parsed_cnt}. Total filtered packets: {total_filtered_cnt}.")
    
def generator_logger():
    print('ok')