require 'test/unit'
require 'nvd_repo'

class NvdFileSystemTest < Test::Unit::TestCase

  TEST_ROOT='test/data/rut'

  def clean_fs
    `rm -rf #{TEST_ROOT}`
  end

  def test_creates_root_path
    clean_fs
    nvdfs = NvdFileSystem.new(TEST_ROOT)
    assert Dir.exist?(nvdfs.root_path), "Should have created new dir"
  end

  def test_import
    clean_fs
    assert_equal false,Dir.exist?("#{TEST_ROOT}/2016")
    nvdfs = NvdFileSystem.new(TEST_ROOT)
    nvdfs.import './test/data/nvdcve-Recent-20160420.xml.gz'
    assert Dir.exist?("#{nvdfs.root_path}/2016")

    path="#{nvdfs.root_path}/2016/CVE-2016-4009/2016-04-13.json"
    assert File.exist?(path)
    assert File.size(path) > 0

    clean_fs
  end

end

