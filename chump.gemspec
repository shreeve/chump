# encoding: utf-8

Gem::Specification.new do |s|
  s.name        = "chump"
  s.version     = "0.5.2"
  s.author      = "Steve Shreeve"
  s.email       = "steve.shreeve@gmail.com"
  s.summary     = "Chump is an interactive session scripting tool"
  s.description = "Chump can be used to easily script terminal interactions."
  s.homepage    = "https://github.com/shreeve/chump"
  s.license     = "MIT"
  s.files       = `git ls-files`.split("\n") - %w[.gitignore]
end
