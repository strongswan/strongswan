#
# DUMM for Ruby
#

require "mkmf"

dir_config("dumm")

unless find_header('library.h', '../../libstrongswan') and
       find_header('dumm.h', '..')
  puts "... failed: one or more header files not found!"
  exit
end

unless find_library('dumm', 'dumm_create')
  puts "... failed: 'libdumm' not found!"
  exit
end

create_makefile("dumm")

