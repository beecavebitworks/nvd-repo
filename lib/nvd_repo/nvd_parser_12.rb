# Parses NVD v1.2.1 data file (.xml.gz)  Can optionally download from url.

require 'nokogiri'
require 'zlib'
require 'open-uri'
require 'json'

URL_NVD_FEED_RECENT   = "https://nvd.nist.gov/download/nvdcve-Recent.xml.gz"
URL_NVD_FEED_MODIFIED = "https://nvd.nist.gov/download/nvdcve-Modified.xml.gz"

class NvdParser12

  def initialize
    @listener=nil
    @ignore_if_missing_severity=false
  end

  #---------------------------------------------------------------------
  # Add a listener to receive callbacks:
  #   listener.on_entry_xml(name,date_string,xml_string)
  #   listener.on_entry_json(name,date_string,json_string)
  #---------------------------------------------------------------------
  def add_xml_listener(l)
    @listener = l
  end

  #---------------------------------------------------------------------
  # remove listener
  #---------------------------------------------------------------------
  def remove_xml_listener
    @listener=nil
  end

  #---------------------------------------------------------------------
  # Currently only supports file or urls in .xml.gz format
  # returns array of hashes from parse_entry()
  #---------------------------------------------------------------------
  def parse(url)

    xml_string = nil

    begin
      source = open(url)

      gz = Zlib::GzipReader.new(source)
      xml_string = gz.read
    rescue Exception => ex
      puts "Error downloading : #{ex.message}"
      return nil
    end

    doc = Nokogiri::XML(xml_string.gsub(/[\r\n]/,''))
    if doc.errors.length > 0
      puts "Error parsing XML"
      return nil
    end

    entries = parse_entries(doc)
  end

  #---------------------------------------------------------------------
  #
  #---------------------------------------------------------------------
  def parse_xml_file_single(file_path)
    xml_string=nil

    begin
      f = open(file_path)
      xml_string = f.read
    rescue Exception => ex

      puts "Exception #{ex.message}"
      return nil
    end

    parse_entry_xml(xml_string)
  end

  #---------------------------------------------------------------------
  # Parse an XML document containing a single entry
  #---------------------------------------------------------------------
  def parse_entry_xml(xml_string)
    #xml_string = "<?xml version='1.0' encoding='UTF-8'?>" + xml_string
    doc = Nokogiri::XML(xml_string.gsub(/[\r\n]/,''))
    if doc.errors.length > 0
      return nil
    end
    parse_entry(doc.children[0])
  end

  #---------------------------------------------------------------------
  # parse all entries in Nokogiri document
  #---------------------------------------------------------------------
  def parse_entries(doc)
    entries=[]
    entry_nodes = doc.children[0].children
    entry_nodes.each {|entry_node|
      next unless entry_node[:name]

      entry = parse_entry(entry_node)
      next if entry.nil?

      entries.push entry
      #print_entry entry
    }
    entries
  end

  #---------------------------------------------------------------------
  # This takes a nokogiri node and returns a hash containing a subset of extracted data.
  # If @listener is set, on_entry_xml and on_entry_json will be called.
  # I
  #---------------------------------------------------------------------
  def parse_entry(entry_node)

    @listener.on_entry_xml entry_node[:name], entry_node[:modified] || entry_node[:published], entry_node.to_s if @listener && @listener.respond_to?(:on_entry_xml)

    #return nil unless @ignore_if_missing_severity && entry_node[:severity]

    entry = { name:entry_node[:name],
              refs:[], vuln_prods:[],
              published: entry_node[:published], modified: entry_node[:modified],
              severity:entry_node[:severity],
              seq:entry_node[:seq],
              type: entry_node[:type],
              reject: entry_node[:reject] }

    entry[:vector] = entry_node[:CVSS_vector] if entry_node[:CVSS_vector]

    entry_node.children.each { |c|
      next if c.name == 'text'

      if c.name == 'desc'
        entry[:desc] = c.content
        entry[:desc_source] = c.children[0][:source]

      elsif c.name == 'refs'
        entry[:refs] = parse_refs(c.children)

      elsif c.name == 'vuln_soft'
        entry[:vuln_prods] = parse_vuln_soft(c.children)

      else
        #puts "node #{c.name} ?"
      end
    }

    @listener.on_entry_json entry_node[:name], entry_node[:modified] || entry_node[:published], entry.to_json if @listener && @listener.respond_to?(:on_entry_json)

    @listener.on_entry entry if @listener && @listener.respond_to?(:on_entry)

    entry
  end

  #---------------------------------------------------------------------
  # prints entry - for development
  #---------------------------------------------------------------------
  def self.print_entry(entry)
    if entry[:reject]
      str = "#{entry[:name]} REJECTED #{entry[:published]}"
    else
      str = "#{entry[:name]} severity:#{entry[:severity]} #{entry[:published]} refs:#{entry[:refs].length} prods:#{entry[:vuln_prods].length} "
      str += "\n  #{entry[:desc][0,80]}"
      entry[:vuln_prods].each {|prod|
        str += "\n  #{prod[:vendor]} #{prod[:name]}  (#{prod[:versions].length} versions) "
      }
    end
    puts str
  end

  #---------------------------------------------------------------------
  # assumes name is CVE format "CVE-year-number"  e.g. "CVE-2016-2923"
  #---------------------------------------------------------------------
  def self.year_from_name(name)
    a=name.split('-')
    a[1]
  end

  #---------------------------------------------------------------------
  # Parses references
  #---------------------------------------------------------------------
  def parse_refs(ref_nodes)
    retval=[]
    ref_nodes.each {|node|
      next unless node[:url]
      ref = {source:node[:source], url:node[:url], label:node.content.strip}
      retval.push ref
    }
    retval
  end

  #---------------------------------------------------------------------
  # Parses software products
  # returns array of
  #   vuln_prod hashes: {:name, :vendor, :versions [] }
  #   version hash: {num: "1.2.3"} or {num:"v233.3", edition:'mobile'}
  #---------------------------------------------------------------------
  def parse_vuln_soft(prod_nodes)
    retval=[]
    prod_nodes.each { |p|
      next if p.name == 'text'
      # puts "product name=#{p[:name]} vendor=#{p[:vendor]}"

      prod = {name:p[:name], vendor: p[:vendor], versions:[]}
      retval.push prod

      p.children.each {|c|
        next unless c[:num]
        #puts "vers #{c[:num]} #{c[:edition]}"

        v = {num: c[:num]}
        v[:edition] = c[:edition] if c[:edition]
        prod[:versions].push ( v )
      }
    }
    retval
  end

  #---------------------------------------------------------------------
  # Fetch, parse, return entries for recent nvd v1.2 feed
  #---------------------------------------------------------------------
  def self.fetch_and_parse_nvd_recent
    parser = NvdParser12.new
    entries = parser.parse(URL_NVD_FEED_RECENT)
  end

  #---------------------------------------------------------------------
  # Fetch, parse, return entries for modified nvd v1.2 feed
  #---------------------------------------------------------------------
  def self.fetch_and_parse_nvd_modified
    parser = NvdParser12.new
    entries = parser.parse(URL_NVD_FEED_MODIFIED)
  end

  #---------------------------------------------------------------------
  # Fetch, parse and return entries for filepath.
  # @param entry_listener  (optional) If present, will add listener to parser
  #---------------------------------------------------------------------
  def parse_file(filepath, entry_listener=nil)
    add_xml_listener entry_listener if entry_listener
    entries = parse(filepath)
  end

  #---------------------------------------------------------------------
  # creates new parser instance and calls parse_file
  #---------------------------------------------------------------------
  def self.parse_file(filepath, entry_listener=nil)
    parser = NvdParser12.new
    parser.parse_file(filepath, entry_listener)
  end
end

if __FILE__ == $0



  file="data/nvd/archive/nvdcve-2015.xml.gz"
#  file="data/nvd/archive/nvdcve-2016.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160320.xml.gz"
   entries = NvdParser12.parse_file file, listener


  parser = NvdParser12.new
  entries.each {|e|

#    NvdParser12.print_entry e
  }
end

