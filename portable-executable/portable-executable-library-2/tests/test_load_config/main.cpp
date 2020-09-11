#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void check_load_config(const image_config_info& info)
{
	PE_TEST(info.get_security_cookie_va() == 0x41E7F4, "Load Config Values test 1", test_level_normal);
	PE_TEST(info.get_se_handler_count() == 0x20, "Load Config Values test 2", test_level_critical);
	PE_TEST(info.get_time_stamp() == 0, "Load Config Values test 3", test_level_normal);
	PE_TEST(info.get_se_handler_rvas()[1] == 0x731a, "Load Config Values test 4", test_level_normal);
}

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));

	if(image.get_pe_type() == pe_type_32)
	{
		image_config_info info;
		PE_TEST_EXCEPTION(info = get_image_config(image), "Load Config Parser test 1", test_level_critical);
		check_load_config(info);

		section s;
		s.get_raw_data().resize(1);
		s.set_name("newcfg");
		section& new_config_section = image.add_section(s);

		uint32_t old_dir_rva = image.get_directory_rva(pe_win::image_directory_entry_load_config);

		PE_TEST_EXCEPTION(rebuild_image_config(image, info, new_config_section, 0, false, false, true, true), "Load Config Rebuilder test 1", test_level_critical);
		PE_TEST(old_dir_rva != image.get_directory_rva(pe_win::image_directory_entry_load_config), "Load Config test 5", test_level_normal);

		uint64_t old_se_handler_table_va = info.get_se_handler_table_va();
		PE_TEST_EXCEPTION(info = get_image_config(image), "Load Config Parser test 2", test_level_critical);
		PE_TEST(old_se_handler_table_va == info.get_se_handler_table_va(), "Load Config test 5", test_level_normal);
		check_load_config(info);

		PE_TEST_EXCEPTION(rebuild_image_config(image, info, new_config_section, 0, true, false, true, true), "Load Config Rebuilder test 2", test_level_critical);
		PE_TEST_EXCEPTION(info = get_image_config(image), "Load Config Parser test 3", test_level_critical);
		PE_TEST(old_se_handler_table_va != info.get_se_handler_table_va(), "Load Config test 6", test_level_normal);
		check_load_config(info);

		info.add_lock_prefix_rva(0x123);
		info.add_lock_prefix_rva(0x456);
		info.add_lock_prefix_rva(0x789);

		PE_TEST_EXCEPTION(rebuild_image_config(image, info, new_config_section, 0, true, true, true, true), "Load Config Rebuilder test 3", test_level_critical);
		PE_TEST_EXCEPTION(info = get_image_config(image), "Load Config Parser test 4", test_level_critical);
		check_load_config(info);
		PE_TEST(info.get_lock_prefix_rvas().size() == 3, "Load Config Lock Prefix test 1", test_level_normal);
		PE_TEST(info.get_lock_prefix_rvas()[2] == 0x789, "Load Config Lock Prefix test 2", test_level_normal);
		
		PE_TEST_EXCEPTION(rebuild_image_config(image, info, new_config_section, 1, true, true, true, true), "Load Config Rebuilder test 4", test_level_critical);
		PE_TEST_EXCEPTION(info = get_image_config(image), "Load Config Parser test 5", test_level_critical);
		check_load_config(info);
		PE_TEST_EXCEPTION(rebuild_image_config(image, info, new_config_section, 12, true, true, true, true), "Load Config Rebuilder test 5", test_level_critical);
		PE_TEST_EXCEPTION(info = get_image_config(image), "Load Config Parser test 6", test_level_critical);
		check_load_config(info);

		info.add_se_handler_rva(0x001); //Check sorting
		info.set_lock_prefix_table_va(0);
		PE_TEST_EXCEPTION(rebuild_image_config(image, info, new_config_section, 0, true, false, true, true), "Load Config Rebuilder test 5", test_level_critical);
		PE_TEST_EXCEPTION(info = get_image_config(image), "Load Config Parser test 6", test_level_critical);
		PE_TEST(info.get_se_handler_count() == 0x21, "Load Config Values test 5", test_level_critical);
		PE_TEST(info.get_se_handler_rvas()[0] == 0x001, "Load Config Values test 6", test_level_normal); //Checks if list is sorted
	}

	PE_TEST_END

	return 0;
}
