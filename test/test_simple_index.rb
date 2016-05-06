require 'test/unit'
require 'nvd_repo'

class NvdfsSimpleIndexTest < Test::Unit::TestCase

  TEST_FILE='test/data/simple-index-example.txt'

  def test_load
    idx = NvdfsSimpleIndex.load TEST_FILE
    assert_equal 11,idx.num
  end

  def test_get
    idx = NvdfsSimpleIndex.load TEST_FILE
    entries = idx.entries_for_severity 'High'
    assert_equal 8,entries.length

    assert entries.include? 'CVE-2016-0088'
    assert entries.include? 'CVE-2016-0167'
    assert entries.include? 'CVE-2016-0145'

    assert_equal entries.length, idx.entries_for_severity('high').length, "severity should be case insensitive"

    assert_equal 1, idx.entries_for_severity('medium').length
    assert_equal 'CVE-2016-0128', idx.entries_for_severity('MEDIUM').first

    assert_equal 2, idx.entries_for_severity('low').length
  end

  def test_missing_file
    idx = NvdfsSimpleIndex.load 'test/data/some_file_that_shouldnt_exist'
    assert_equal 0,idx.entries.length
  end

  def test_save
    path="test/data/index_test_#{Random.rand(99999).to_i}"

    idx = NvdfsSimpleIndex.load path
    idx.add('High', 'first')
    idx.add('High', 'second')
    idx.add('Low', 'third')
    idx.add('Medium', 'fourth')

    idx.save

    assert File.exist? path

    loaded = NvdfsSimpleIndex.load path
    assert_equal idx.num, loaded.num

    `rm #{path}`
  end

end

