# logstashRubyFilter
# Use this filter to parse JUnit test results:

If you have cobertura xml or junit tests results and want to upload them to ELK stack -
1. Copy .rb files to the Logstash filters folder
2.  Restart logstash (Optional)

*In my scenario, I'm dumping the cobertura.xml and junit test results into redis (base64 encoded)
The logstash pipeline, picks up the entry and using the filters, it parses and send it to Elasticsearch.
