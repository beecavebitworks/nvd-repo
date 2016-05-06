class NvdfsSimpleIndex

  def initialize path
    @path = path
    @sevmap={}
  end

  def num
    val=0
    @sevmap.each {|key,entries| val += entries.length}
    val
  end

  # returns instance
  def self.load(path)
    obj = NvdfsSimpleIndex.new path
    obj._load path
    obj
  end

  def entries_for_severity(raw_severity)
    return [] if raw_severity.nil?
    severity = raw_severity.downcase
    return [] unless @sevmap.include? severity
    @sevmap[severity]
  end

  def entries
    val=[]
    @sevmap.each {|severity,entries| entries.each {|entry| val << entry}}
    val
  end

  def add(raw_severity, name)
    severity = raw_severity.downcase
    @sevmap[severity] = [] unless @sevmap.include? severity
    @sevmap[severity] << name unless @sevmap[severity].include? name
  end

  def save
    begin
      File.open(@path, "wb") {|f|
        @sevmap.each {|severity, entries|
          f.write "#{severity}=#{entries.join(',')}\n"
        }
      }
    rescue Exception => ex
      puts "Exception saving index #{@path} : #{ex.message}"
    end
  end

 # private

  # returns none
  def _load(path)
    return unless File.exist? path

    begin
      File.open(path, "r") {|f|
        f.readlines.each {|line|
          line.strip!
          next if line.length <= 0

          sev,str = line.split '='
          entries = str.split(',')
          @sevmap[sev] = entries
        }
      }
    rescue Exception => e
      str = "error reading index at #{path}"
      puts str
    end
  end



end