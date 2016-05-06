require 'test/unit'
require 'nvd_repo'

class NvdParseTest < Test::Unit::TestCase


  def test_basic_parse

    parser = NvdParser12.new
    entry = parser.parse_xml_file_single('test/data/nvdcve-12.sample.xml')
    assert_equal false, entry.nil?

    assert_equal 'CVE-2015-5343', entry[:name]
    assert_equal 'High', entry[:severity]
    assert_equal '2016-04-19', entry[:modified]
    assert_equal '2016-04-14', entry[:published]


    assert_equal 3, entry[:refs].length
    assert_equal 'CONFIRM', entry[:refs][2][:source]

    assert_equal 2,entry[:vuln_prods].length
    assert_equal 'subversion', entry[:vuln_prods][0][:name]
    assert_equal 'apache', entry[:vuln_prods][0][:vendor]

  end

end
