from pathway_app import LogProcessor
p = LogProcessor(enable_drain3=False)
print(p.process_line('{\"level\": \"info\", \"src_ip\": \"10.0.0.1\"}'))
print(p.process_line('<134>Oct 11 22:14:15 asa01 %ASA-6-302013: Teardown TCP connection 1234 for host 10.0.0.1:80 to host 8.8.8.8:443, duration 5s, bytes 1500'))
p.print_summary()