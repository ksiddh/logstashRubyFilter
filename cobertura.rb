# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# XML filter. Takes a field that contains XML and expands it into
# an actual datastructure.
class LogStash::Filters::Cobertura < LogStash::Filters::Base
    
    config_name "cobertura"
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
        
        coverageNodeset = doc.xpath("coverage")
        coveragenode = coverageNodeset.first
        
        matched = true
        
        event_coverage = event.clone
        @logger.debug("Split coverage event", :value => value, :field => @field)
        
        event_coverage["type"] = 'cobertura_coverage'
        event_coverage["message"] = coveragenode.to_s
        
        event_coverage["coverage_line-rate"] = (coveragenode['line-rate'].to_f) * 100
        event_coverage["coverage_branch-rate"] = (coveragenode['branch-rate'].to_f) * 100
        event_coverage["coverage_lines-covered"] = coveragenode['lines-covered'].to_i
        event_coverage["coverage_lines-valid"] = coveragenode['lines-valid'].to_i
        event_coverage["coverage_branches-covered"] = coveragenode['branches-covered'].to_i
        event_coverage["coverage_branches-valid"] = coveragenode['branches-valid'].to_i
        event_coverage["coverage_complexity"] = coveragenode['complexity'].to_f
        event_coverage["coverage_version"] = coveragenode['version']
        event_coverage["coverage_timestamp"] = coveragenode['timestamp']
        
        sourceNodeset = doc.xpath("/coverage/sources/source")
        
        if sourceNodeset.length > 0
          $i = 1
          sourceNodeset.each do |sourcenode|
              event_coverage["coverage_source" + $i.to_s] = sourcenode.text
              $i +=1
          end
        end
        
        filter_matched(event_coverage)
        
        # Push this new event onto the stack at the LogStash::FilterWorker
        yield event_coverage
        
        packageNodeset = doc.xpath("/coverage/packages/package")
        if packageNodeset.length > 0
          packageNodeset.each do |packagenode|
            # some XPath functions return empty arrays as string
            if packagenode.is_a?(Array)
                return if packagenode.length == 0
            end
            
            unless packagenode.nil?
                matched = true
                
                package_guid = SecureRandom.uuid
                
                event_package = event.clone
                @logger.debug("Split package event", :value => value, :field => @field)
                
                event_package["type"] = 'cobertura_package'
                event_package["message"] = packagenode.to_s
                
                event_package["package_guid"] = package_guid
                event_package["package_name"] = packagenode['name']
                
                event_package["package_line-rate"] = (packagenode['line-rate'].to_f) * 100
                event_package["package_branch-rate"] = (packagenode['branch-rate'].to_f) * 100
                #event_package["package_complexity"] = packagenode['complexity'].to_f
                
                packagenode.children.first.children.each do |classnode|
                    class_guid = SecureRandom.uuid
                    
                    event_class = event.clone
                    @logger.debug("Split class event", :value => value, :field => @field)
                    
                    event_class["type"] = 'cobertura_class'
                    event_class["message"] = classnode.to_s
                    
                    event_class["package_guid"] = package_guid
                    event_class["package_name"] = packagenode['name']
                    
                    event_class["class_guid"] = class_guid
                    event_class["class_name"] = classnode['name']
                    event_class["class_filename"] = classnode['filename']
                    event_class["class_line-rate"] = (classnode['line-rate'].to_f) * 100
                    event_class["class_branch-rate"] = (classnode['branch-rate'].to_f) * 100
                    #event_class["class_complexity"] = classnode['complexity'].to_f
                    
                    filter_matched(event_class)
                    
                    # Push this new event onto the stack at the LogStash::FilterWorker
                    yield event_class
                    
                    classnode.children.first.children.each do |methodnode|
                        event_method = event.clone
                        @logger.debug("Split method event", :value => value, :field => @field)
                        
                        event_method["type"] = 'cobertura_method'
                        event_method["message"] = methodnode.to_s
                        
                        event_method["package_guid"] = package_guid
                        event_method["package_name"] = packagenode['name']
                        
                        event_method["class_guid"] = class_guid
                        event_method["class_name"] = classnode['name']
                        
                        event_method["method_name"] = methodnode['name']
                        event_method["method_signature"] = methodnode['signature']
                        #event_method["method_line-rate"] = (methodnode['line-rate'].to_f) * 100
                        #event_method["method_branch-rate"] = (methodnode['branch-rate'].to_f) * 100
                        
                        filter_matched(event_method)
                        
                        # Push this new event onto the stack at the LogStash::FilterWorker
                        yield event_method
                    end
                end
                
                filter_matched(event_package)
                
                # Push this new event onto the stack at the LogStash::FilterWorker
                yield event_package
            end
          end # XPath.each
        end
        
        filter_matched(event) if matched
        @logger.debug("Event after cobertura filter", :event => event)
        
        # Cancel this event, we'll use the newly generated ones above.
        event.cancel
    end # def filter
end # class LogStash::Filters::Cobertura
