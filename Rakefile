require 'rake'
require 'rake/testtask'
require 'rdoc'

desc 'Default: run unit tests.'
task :default => :test

desc 'Test the devise_pam_authenticatable plugin.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.libs << 'test'
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
end

desc 'Generate documentation for the devise_pam_authenticatable plugin.'
RDoc::Task.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'DevisePAMAuthenticatable'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "devise_pam_authenticatable2"
    gemspec.summary = "Devise PAM authentication module using rpam2"
    gemspec.description = "For authenticating against PAM (Pluggable Authentication Modules)"
    gemspec.email = "devkral@web.de"
    gemspec.homepage = "http://github.com/devkral/devise_pam_authenticatable2"
    gemspec.license = "MIT"
    gemspec.authors = ["James Wilson", "Alexander Kaftan"]
    gemspec.add_runtime_dependency "devise", ">= 4.0.0"
    gemspec.add_runtime_dependency "rpam2", "~> 4.0"
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end
