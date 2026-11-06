import os
import subprocess

from conan import ConanFile
from conan.errors import ConanException
from conan.tools.scm import Git
from conan.tools.files import update_conandata
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.build import check_min_cppstd

class Xtun(ConanFile):
    name = "xtun"
    user = "amnezia"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "bundle_goxtun": [True, False],
        "bundle_wintun": [True, False],
    }
    default_options = { "shared": False, "fPIC": True, "bundle_goxtun": True, "bundle_wintun": True }
    generators = "VirtualBuildEnv", "CMakeConfigDeps"
    implements = ["auto_shared_fpic"]

    def set_version(self):
        if self.version:
            return
        script = os.path.join(self.recipe_folder, "cmake", "version.cmake")
        version = subprocess.check_output(["cmake", "-P", script], text=True).strip()
        if not version:
            raise ConanException(f"'cmake -P {script}' printed no version")
        self.version = version

    def requirements(self):
        if self.options.bundle_wintun and self.settings.os == "Windows":
            self.requires("wintun/0.14.1@amnezia")
        if self.settings.os == "Windows" and self.settings.arch == "x86_64":
            self.requires("win-split-tunnel/1.2.5.0@amnezia", headers=False, libs=False, run=True)
        if self.settings.os == "Linux":
            self.requires("libsystemd/262.2")
    
    def build_requirements(self):
        self.tool_requires("go/[>=1.27]@amnezia")
        if self.settings.os == "Windows":
            self.tool_requires("mingw-builds/15.1.0")
        self.test_requires("gtest/1.17.0")

    def validate_build(self):
        # xtun requires c++20 for building. however, runtime features are limited by c++17
        check_min_cppstd(self, 20)

    def validate(self):
        check_min_cppstd(self, 17)

    def export(self):
        git = Git(self, self.recipe_folder)
        url, commit = git.get_url_and_commit()
        update_conandata(self, {"sources": {"url": url, "commit": commit}})

    def source(self):
        git = Git(self)
        data = self.conan_data["sources"]
        git.clone(url=data["url"], target=".")
        git.checkout(commit=data["commit"])

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.user_presets_path = False
        tc.cache_variables["BUNDLE_GOXTUN"] = bool(self.options.bundle_goxtun)
        tc.cache_variables["BUNDLE_WINTUN"] = bool(self.options.bundle_wintun)
        tc.cache_variables["BUILD_TESTS"] = False
        tc.cache_variables["USE_CONAN_PROVIDER"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::xtun")
        self.cpp_info.libs = ["xtun", "libgoxtun"] if self.settings.os == "Windows" else ["xtun", "goxtun"]
        if self.settings.os == "Windows":
            self.cpp_info.system_libs = ["iphlpapi", "ws2_32", "fwpuclnt", "advapi32"]
            self.cpp_info.defines = ["WIN32_LEAN_AND_MEAN", "NOMINMAX"]
        elif self.settings.os in ("Linux", "Android"):
            self.cpp_info.system_libs = ["pthread", "dl"]
        elif self.settings.os in ("Macos", "iOS"):
            self.cpp_info.frameworks = ["SystemConfiguration", "CoreFoundation", "Security"]
            self.cpp_info.system_libs = ["resolv"]
