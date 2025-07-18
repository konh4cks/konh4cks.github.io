# -*- encoding: utf-8 -*-
# stub: bundler 1.13.7 ruby lib

Gem::Specification.new do |s|
  s.name = "bundler".freeze
  s.version = "1.13.7".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 1.3.6".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Andr\u00E9 Arko".freeze, "Samuel Giddins".freeze]
  s.bindir = "exe".freeze
  s.date = "2016-12-25"
  s.description = "Bundler manages an application's dependencies through its entire life, across many machines, systematically and repeatably".freeze
  s.email = ["team@bundler.io".freeze]
  s.executables = ["bundle".freeze, "bundler".freeze]
  s.files = ["exe/bundle".freeze, "exe/bundler".freeze]
  s.homepage = "http://bundler.io".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7".freeze)
  s.rubygems_version = "2.6.8".freeze
  s.summary = "The best way to manage your application's dependencies".freeze

  s.installed_by_version = "3.6.7".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<automatiek>.freeze, ["~> 0.1.0".freeze])
  s.add_development_dependency(%q<mustache>.freeze, ["= 0.99.6".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 10.0".freeze])
  s.add_development_dependency(%q<rdiscount>.freeze, ["~> 2.2".freeze])
  s.add_development_dependency(%q<ronn>.freeze, ["~> 0.7.3".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.5".freeze])
end
