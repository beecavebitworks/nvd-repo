Gem::Specification.new do |s|
  s.name        = 'nvd-repo'
  s.version     = '0.5.0'
  s.date        = '2016-04-18'
  s.summary     = "A way to generate and update a static filesystem for NVD () data feeds"
  s.description = "The goal is to provide a utility to quickly parse User-Agent strings and determine browser, platform, and operating system versions for the most popular http clients with a miminum of regex."
  s.authors     = ["Alex Malone"]
  s.email       = 'originalsix@bluesand.org'
  s.files       = ["lib/nvd_repo.rb", "lib/nvd_repo/nvd_parser.rb" ]
  s.homepage    =
    'https://github.com/beecavebitworks/nvd-repo'
  s.license       = 'Apache 2.0'
end
