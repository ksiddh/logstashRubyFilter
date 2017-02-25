# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# XML filter. Takes a field that contains XML and expands it into
# an actual datastructure.
class LogStash::Filters::Junit < LogStash::Filters::Base
    
    config_name "junit"
    milestone 1
    
    # Config for xml to hash is:
    #
    #     source => source_field
    #
    # For example, if you have the whole xml document in your @message field:
    #
    #     filter {
    #       xml {
    #         source => "message"
    #       }
    #     }
    #
    # The above would parse the xml from the @message field
    config :source, :validate => :string
    
    public
    def register
        require "nokogiri"
        require "xmlsimple"
        require "securerandom"
        require "base64"
    end # def register
    
    public
    def filter(event)
        return unless filter?(event)
        matched = false
        
        @logger.debug("Running xml filter", :event => event)
        
        return unless event.include?(@source)
                
        value = Base64.decode64(event[@source])
        value.gsub!(/>\s+</,"><")
        
        if value.is_a?(Array) && value.length > 1
            @logger.warn("XML filter only works on fields of length 1",
                         :source => @source, :value => value)
          return
        end
        
        # Do nothing with an empty string.
        return if value.strip.length == 0
        
        begin
          doc = Nokogiri::XML(value)
        rescue => e
          event.tag("_xmlparsefailure")
          @logger.warn("Trouble parsing xml", :source => @source, :value => value,
                :exception => e, :backtrace => e.backtrace)
          return
        end
        
        nodeset = doc.xpath("/testsuite")
                
        # If asking xpath for a String, like "name(/*)", we get back a
        # String instead of a NodeSet.  We normalize that here.
        normalized_nodeset = nodeset.kind_of?(Nokogiri::XML::NodeSet) ? nodeset :[nodeset]
       
        normalized_nodeset.each do |testsuitenode|
          # some XPath functions return empty arrays as string
          if testsuitenode.is_a?(Array)
            return if testsuitenode.length == 0
          end
                    
          unless testsuitenode.nil?
            matched = true
            
            event_testsuite = event.clone
            @logger.debug("Split testsuite event", :value => value, :field => @field)
            testsuite_guid = SecureRandom.uuid
            
            event_testsuite["message"] = testsuitenode.to_s
            event_testsuite["type"] = 'junit_testsuite'
            
            event_testsuite["testsuite_guid"] = testsuite_guid
            event_testsuite["testsuite_disabled"] = testsuitenode['disabled']
            event_testsuite["testsuite_errors"] = testsuitenode['errors'].to_i
            event_testsuite["testsuite_failures"] = testsuitenode['failures'].to_i
            event_testsuite["testsuite_hostname"] = testsuitenode['hostname']
            event_testsuite["testsuite_id"] = testsuitenode['id']
            event_testsuite["testsuite_name"] = testsuitenode['name']
            event_testsuite["testsuite_package"] = testsuitenode['package']
            event_testsuite["testsuite_skipped"] = testsuitenode['skipped'].to_i
            event_testsuite["testsuite_tests"] = testsuitenode['tests'].to_i
            event_testsuite["testsuite_time"] = testsuitenode['time'].to_f
            event_testsuite["testsuite_timestamp"] = testsuitenode['timestamp']
            
            testsuitenode.children.each do |testcasenode|
              event_testcase = event.clone
              @logger.debug("Split testcase event", :value => value, :field => @field)
              
              event_testcase["message"] = testcasenode.to_s
              event_testcase["type"] = 'junit_testcase'
              
              event_testcase["testsuite_name"] = testsuitenode['name']
              event_testcase["testsuite_guid"] = testsuite_guid
            
              event_testcase["testcase_name"] = testcasenode['name']
              event_testcase["testcase_assertions"] = testcasenode['assertions']
              event_testcase["testcase_duration"] = testcasenode['time'].to_f
              event_testcase["testcase_classname"] = testcasenode['classname']
              event_testcase["testcase_status"] = testcasenode['status']
            
              if testcasenode.children.count == 0
                event_testcase["testcase_result"] = 'success'
              elsif testcasenode.children.count == 1
                event_testcase["testcase_result"] = testcasenode.children.first.name
                event_testcase["testcase_result_type"] = testcasenode.children.first['type']
                event_testcase["testcase_result_message"] = testcasenode.children.first['message']
                event_testcase["testcase_result_content"] = testcasenode.children.first.text
              else
                $i = 1
                testcasenode.children.each do |child|
                    event_testcase["testcase_result"] = 'various'
                    event_testcase["testcase_result" + $i.to_s] = child.name
                    event_testcase["testcase_result" + $i.to_s + "_type"] = child['type']
                    event_testcase["testcase_result" + $i.to_s + "_message"] = child['message']
                    event_testcase["testcase_result" + $i.to_s + "_content"] = child.text
                    $i +=1
                end
              end
              filter_matched(event_testcase)
              
              # Push this new event onto the stack at the LogStash::FilterWorker
              yield event_testcase
            end
            
            filter_matched(event_testsuite)
            
            # Push this new event onto the stack at the LogStash::FilterWorker
            yield event_testsuite
          end
        end # XPath.each
        
        filter_matched(event) if matched
        @logger.debug("Event after junit filter", :event => event)
        
        # Cancel this event, we'll use the newly generated ones above.
        event.cancel
    end # def filter
end # class LogStash::Filters::Junit