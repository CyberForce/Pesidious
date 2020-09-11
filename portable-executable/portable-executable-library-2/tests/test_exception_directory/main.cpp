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

	if(image.get_pe_type() == pe_type_64)
	{
		exception_entry_list info;
		PE_TEST_EXCEPTION(info = get_exception_directory_data(image), "Exception directory parser test", test_level_critical);
		PE_TEST(info.size() == 0x1C6, "Exception directory test 1", test_level_normal);
		PE_TEST(info[5].get_begin_address() == 0x000011D5
			&& info[5].get_end_address() == 0x00001220, "Exception directory test 2", test_level_normal);
		PE_TEST(info[5].get_flags() == 4, "Exception directory test 3", test_level_normal);
		PE_TEST(info[5].get_unwind_info_address() == 0x21528, "Exception directory test 4", test_level_normal);
		PE_TEST(info[5].get_unwind_info_version() == 1, "Exception directory test 5", test_level_normal);
		PE_TEST(info[5].get_size_of_prolog() == 0x5, "Exception directory test 6", test_level_normal);
		PE_TEST(info[5].get_number_of_unwind_slots() == 2, "Exception directory test 7", test_level_normal);
		PE_TEST(info[5].get_frame_pointer_register_number() == 0, "Exception directory test 8", test_level_normal);
		PE_TEST(info[5].get_scaled_rsp_offset() == 0, "Exception directory test 9", test_level_normal);
	}

	PE_TEST_END

	return 0;
}
