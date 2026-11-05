require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  # One word: React Native's Swift package hook expects the module name to match the pod name.
  s.name         = "TailPocketReactNative"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.license      = package["license"]
  s.homepage     = "https://github.com/jt-wang/tailpocket"
  s.authors      = "tailpocket authors"
  s.platforms    = { :ios => "15.0" }
  s.source       = { :git => "https://github.com/jt-wang/tailpocket.git", :tag => "v#{s.version}" }
  s.source_files = "ios/**/*.{swift,m}"
  s.swift_version = "5.10"
  install_modules_dependencies(s)
  # The Swift package (React Native 0.75+ links Swift packages into pods this way): the checkout this
  # package sits in when there is one (a local path), otherwise the published repository.
  repo = File.expand_path("../..", File.realpath(__dir__))
  swift_package = File.exist?(File.join(repo, "Package.swift")) ? repo : "https://github.com/jt-wang/tailpocket.git"
  spm_dependency(s,
    url: swift_package,
    requirement: { kind: "upToNextMajorVersion", minimumVersion: package["version"] },
    products: ["TailPocket", "TailPocketUI"])
end
