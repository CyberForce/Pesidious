#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));

	basic_dotnet_info info;
	PE_TEST_EXCEPTION(info = get_basic_dotnet_info(image), "Basic Dotnet Info Parser test", test_level_critical);
	PE_TEST(info.get_flags() == 1, "DotNet test 1", test_level_normal);
	PE_TEST(info.get_major_runtime_version() == 2 && info.get_minor_runtime_version() == 5, "DotNet test 2", test_level_normal);
	PE_TEST(info.get_rva_of_metadata() == 0x2064 && info.get_size_of_metadata() == 0x598, "DotNet test 3", test_level_normal);
	PE_TEST(info.get_rva_of_resources() == 0 && info.get_size_of_resources() == 0, "DotNet test 4", test_level_normal);
	PE_TEST(info.get_rva_of_strong_name_signature() == 0 && info.get_size_of_strong_name_signature() == 0, "DotNet test 5", test_level_normal);
	PE_TEST(info.get_rva_of_code_manager_table() == 0 && info.get_size_of_code_manager_table() == 0, "DotNet test 6", test_level_normal);
	PE_TEST(info.get_rva_of_vtable_fixups() == 0 && info.get_size_of_vtable_fixups() == 0, "DotNet test 7", test_level_normal);
	PE_TEST(info.get_rva_of_export_address_table_jumps() == 0 && info.get_size_of_export_address_table_jumps() == 0, "DotNet test 8", test_level_normal);
	PE_TEST(info.get_rva_of_managed_native_header() == 0 && info.get_size_of_managed_native_header() == 0, "DotNet test 9", test_level_normal);
	PE_TEST(info.get_entry_point_rva_or_token() == 0x06000001, "DotNet test 10", test_level_normal);
	PE_TEST(!info.is_native_entry_point(), "DotNet test 11", test_level_normal);
	PE_TEST(!info.is_32bit_required(), "DotNet test 12", test_level_normal);

	PE_TEST_END

	return 0;
}
