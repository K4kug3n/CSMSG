set_project("CSMSG")

add_requires("catch2")

add_rules("mode.debug", "mode.release")
add_rules("plugin.vsxmake.autoupdate")

add_includedirs("include")
add_headerfiles("include/**.hpp", "include/**.inl")
add_files("src/**.cpp")

set_languages("c++17")
set_warnings("allextra")

target("main")
	add_files("example/**.cpp")

target("tests")
	add_files("tests/**.cpp")
	add_packages("catch2")