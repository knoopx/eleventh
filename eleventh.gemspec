# -*- encoding: utf-8 -*-

$:.push File.expand_path("../lib", __FILE__)

require "eleventh/version"

Gem::Specification.new do |s|
  s.name = "eleventh"
  s.version = Eleventh::VERSION
  s.authors = ["Víctor Martínez"]
  s.email = ["knoopx@gmail.com"]
  s.homepage = "http://github.com/knoopx/eleventh"
  s.summary = %q{An automated, all-in-one dictionary generator and WEP cracker}
  s.description = %q{An automated, all-in-one dictionary generator and WEP cracker}

  s.files = `git ls-files`.split("\n")
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency "bindata"
  s.add_dependency "activesupport"
end
