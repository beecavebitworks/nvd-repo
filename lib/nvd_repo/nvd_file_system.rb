NVDFS_ROOT="./data/nvd"
START_YEAR=2012
BASE_URL="https://nvd.nist.gov/download/"

class NvdFileSystem

  attr_accessor :root_path, :enable_xml_save

  def initialize(root)
    root = NVDFS_ROOT if root.nil?
    self.root_path= root
    @parser_listener = nil
    @enable_xml_save = true

  end

  #-----------------------------------------------------
  # set root_path and create directory if not present
  #-----------------------------------------------------
  def root_path=(str)
    @root_path=str
    Dir.mkdir @root_path unless Dir.exist? @root_path
  end

  #-----------------------------------------------------
  # path to directory for CVE files
  # TODO: can get ROOT from ENV or config value?
  #-----------------------------------------------------
  def _entry_path(cve_name)
    year = NvdFileSystem.year_from_name(cve_name)
    "#{@root_path}/#{year}/#{cve_name}/"
  end

  #-----------------------------------------------------
  # Get handle to parser listener
  #-----------------------------------------------------
  def parser_listener
    # create on demand.  not always used
    @parser_listener = NvdFsParserListener.new(self,@enable_xml_save) if @parser_listener.nil?
    @parser_listener
  end

  #-----------------------------------------------------
  # Gets the most recent xml or json entry for cve on file system
  #-----------------------------------------------------
  def last_entry(cve_name, ext, before_date=nil)
    path = self._entry_path(cve_name)

    d=nil
    d=Date.parse(before_date) rescue nil unless before_date.nil?

    dates=[]
    # get dates of current files
    Dir["#{path}/2*.#{ext}"].each { |ipath|
      begin
        file_date_str = ipath.split('/').last.split('.').first
        file_date = Date.parse(file_date_str)
        dates << file_date if d.nil? || file_date < d
      end
    }

    return nil if dates.length == 0

    dates.sort

    filepath=File.join(path, "#{dates.last.to_s}.#{ext}")

    return nil unless File.exist? (filepath)
    str = nil
    begin
      File.open(filepath) { |f| str = f.read }
    end
    str
  end

  def last_xml(cve_name, before_date=nil)
    last_entry(cve_name, 'xml', before_date)
  end
  def last_json(cve_name, before_date=nil)
    last_entry(cve_name, 'json', before_date)
  end

  #-----------------------------------------------------
  # assumes name is CVE format "CVE-year-number"  e.g. "CVE-2016-2923"
  #-----------------------------------------------------
  def self.year_from_name(name)
    a=name.split('-')
    a[1]
  end

  #-----------------------------------------------------
  # Called from 'rake nvd:populate'
  # https://nvd.nist.gov/download/nvdcve-2013.xml.gz
  # TODO: specify nvd version (2.0 or 1.2)
  #-----------------------------------------------------
  def populate

    parser=NvdParser12.new

    (START_YEAR .. Date.today.year).each {|yr|
      url="#{BASE_URL}nvdcve-#{yr}.xml.gz"
      puts "Populating..." + url.to_s
      entries = parser.parse_file url, self.parser_listener

      break
    }
  end


  # TODO: fix path separators

  def _get_index_dir_paths(vendor_product_id, year=nil)
    paths=[]
    path="#{root_path}/index"

    if year.nil?

      # get list of all year subdirectories

      Dir.entries(path).each { |year_subdir|

        next if year_subdir == '.' || year_subdir == '..'

        tmp="#{path}/#{year_subdir}/#{vendor_product_id}"
        paths << tmp if Dir.exist? tmp
      }

    else
      paths << "#{path}/#{year}/#{vendor_product_id}"
    end

    paths
  end

  def _get_index_paths(vendor_product_id, year=nil)
    paths=[]
    path="#{root_path}/index"

    if year.nil?

      # get list of all year subdirectories

      Dir.entries(path).each { |year_subdir|

        next if year_subdir == '.' || year_subdir == '..'

        tmp="#{path}/#{year_subdir}/#{vendor_product_id}"
        paths << tmp if File.exist? tmp
      }

    else
      paths << "#{path}/#{year}/#{vendor_product_id}"
    end

    paths
  end

  #-----------------------------------------------------
  # requires exact vendor:product_id
  #-----------------------------------------------------
  def entries_for_prod vendor_product_id, year=nil, severity=nil

    entries=[]
    paths=_get_index_paths(vendor_product_id, year)
    paths.each { |path|
      next unless File.exist? path

      idx = NvdfsSimpleIndex.load path
      if severity.nil?
        idx.entries.each {|item| entries << item}
      else
        idx.entries_for_severity(severity).each{|item| entries << item}

      end
    }

    entries
  end

  #-----------------------------------------------------
  # requires exact vendor:product_id
  # Uses file-based entries for index
  #-----------------------------------------------------
  def entries_for_prod_dir vendor_product_id, year=nil

    entries=[]
    paths=_get_index_paths(vendor_product_id, year)
    paths.each { |path|
      Dir.entries(path).each {|entry_name|
        next if entry_name == '.' || entry_name == '..'
        entries << entry_name}
    }

    entries
  end


  #-----------------------------------------------------
  #
  #-----------------------------------------------------
  def import(url)
    parser=NvdParser12.new

    puts "Importing... " + url.to_s
    entries = parser.parse_file url, self.parser_listener

  end

  #-----------------------------------------------------
  # Called from 'rake nvd:update'
  #-----------------------------------------------------
  def update
    puts "Updating..."
  end

  #=====================================================
  # NvdParser12 listener that writes entries to NvdFileSystem
  #-----------------------------------------------------
  class NvdFsParserListener

    def initialize(nvdfs, enable_xml=true)
      @nvdfs=nvdfs
      @enable_xml = enable_xml
    end

    #-----------------------------------------------------
    # name : name of entry.  e.g. "CVE-2016-2034"
    # date_str : date of update e.g. '2016-03-08'
    #-----------------------------------------------------
    def on_entry_str(name, date_str, str, ext)

      return if ext == 'xml' && @enable_xml === false

      year = NvdFileSystem::year_from_name(name)

      path = "#{@nvdfs.root_path}/#{year}"
      Dir.mkdir path unless Dir.exist? path
      path += "/#{name}"
      Dir.mkdir path unless Dir.exist? path

      # write dated file

      file = "#{path}/#{date_str}.#{ext}"
      begin
        File.open(file,"wb") {|f| f.write(str) }
      rescue Exception => ex
        str="unable to write to file #{file}"
        puts str
      end

      # write entry.xml - used as most recent

#      file = "#{path}/entry.#{ext}"
#      begin
#        File.open(file,"wb") {|f| f.write(str) }
#      rescue Exception => ex
#        str="unable to write to file #{file}"
#        puts str
#      end

#    puts "path=#{path} #{str.length} bytes #{ext}"
    end

    #-----------------------------------------------------
    # name : name of entry.  e.g. "CVE-2016-2034"
    # date_str : date of update e.g. '2016-03-08'
    #-----------------------------------------------------
    def on_entry_json(name, date_str, json_string)
      on_entry_str(name, date_str, json_string, "json")
    end

    def on_entry_xml(name, date_str, xml_string)
      on_entry_str(name, date_str, xml_string, "xml")
    end


    def on_entry(entry)
      return unless entry[:vuln_prods]
      entry[:vuln_prods].each {|vp|
        idx="#{vp[:vendor]}:#{vp[:name]}"
        add_to_index(idx, entry[:name], entry[:severity])
      }
    end

    #-----------------------------------------------------
    # Creates an empty file with path
    #   <%root>/index/<year>/<idx>/<name>
    #
    #-----------------------------------------------------
    def add_to_index_files(idx, name)
      year = NvdFileSystem::year_from_name(name)

      path="#{@nvdfs.root_path}/index"
      Dir.mkdir path unless Dir.exist? path
      path += "/#{year}"
      Dir.mkdir path unless Dir.exist? path
      path += "/#{idx}"
      Dir.mkdir path unless Dir.exist? path
      path += "/#{name}"

      begin
        File.open(path,"wb") {|f| f.write("") }
      rescue Exception => ex
        str="unable to create index file #{path}"
        puts str
      end

    end

    #-----------------------------------------------------
    # Appends name to appropriate comma-delimited list in file
    #   <%root>/index/<year>/<idx>
    #
    # each line is format 'severity=entry1,entry2,entry3'
    #
    #-----------------------------------------------------
    def add_to_index(vendor_prod_id, name, severity)
      year = NvdFileSystem::year_from_name(name)

      path="#{@nvdfs.root_path}/index"
      Dir.mkdir path unless Dir.exist? path
      path += "/#{year}"
      Dir.mkdir path unless Dir.exist? path
      path += "/#{vendor_prod_id}"


      idx = NvdfsSimpleIndex.load path
      idx.add(severity, name)
      idx.save

    end

  end


end



if $0 == __FILE__
  require './lib/nvd_parser.rb'

  parser = NvdParser.new

  nvdfs = NvdFileSystem.new NVDFS_ROOT
  listener = nvdfs.parser_listener

#  file="data/nvd/archive/nvdcve-2015.xml.gz"
#  file="data/nvd/archive/nvdcve-2016.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160225.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160315.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160317.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160320.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160321.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160412.xml.gz"
#  file="data/nvd/modified/nvdcve-Modified-20160419.xml.gz"
#  file="data/nvd/recent/nvdcve-Recent-20160419.xml.gz"

  entries = parser.parse_file file, listener

  entries.each {|e|

    prev=nil

    str = nvdfs.last_xml(e[:name])
    unless str.nil?
      # load prev
      prev = parser.parse_entry_xml(str)
      if prev.nil?
        # parse may not have failed.  Uncategorized entries (severity and vuln_prods not set) also return nil
#        puts "Parse failed for nvdfs #{e[:name]} str=#{str}"
      else
        prev = nil if (prev[:modified] && prev[:modified] == e[:modified])  # picked up same
      end
    end

    str = "#{e[:name]} #{e[:modified]}"
    str += " has previous entry #{prev[:published]} #{prev[:modified]}" if prev
    puts str

#    NvdParser.print_entry e
  }

end


