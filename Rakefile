require 'rake/testtask'
require './lib/nvd_repo'

Rake::TestTask.new do |t|
  t.libs << 'test'
end

desc "Run tests"
task :default => :test

namespace :nvd do

  task :populate do
    nvdfs = NvdFileSystem.new(NVDFS_ROOT)
    nvdfs.populate
  end

  task :pop15 do
    nvdfs = NvdFileSystem.new(NVDFS_ROOT)
    nvdfs.import './test/data/nvdcve-Recent-20160420.xml.gz'
  end

  task :cat, [:name] do |t, args|
    nvdfs = NvdFileSystem.new(NVDFS_ROOT)
    v = nvdfs.last_entry args[:name], 'json'
    puts v
  end

  task :for_prod, [:name, :year, :severity] do |t, args|
    nvdfs = NvdFileSystem.new(NVDFS_ROOT)

    ano = args[:year]
    ano=nil if ano.nil? === false && ano.strip.length == 0
    ano=nil if ano.nil? === false && ano.strip == '-'

    severity = args[:severity]
    severity=nil if severity.nil? === false && severity.strip.length == 0

    entries = nvdfs.entries_for_prod args[:name], ano, severity
    puts entries.join(',')
  end

  task :update do
    nvdfs = NvdFileSystem.new(NVDFS_ROOT)
    nvdfs.update
  end

  task :clean do
    if NVDFS_ROOT && NVDFS_ROOT.length > 2
      `rm -rf #{NVDFS_ROOT}`
    end

  end

end

