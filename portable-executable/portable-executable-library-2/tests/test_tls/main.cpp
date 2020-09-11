#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void test_tls(const tls_info& info, const pe_base& image, bool check_callbacks = true)
{
	PE_TEST(info.get_characteristics() == 0, "TLS test 1", test_level_normal);
	PE_TEST(info.get_size_of_zero_fill() == 0, "TLS test 2", test_level_normal);
	PE_TEST(info.get_raw_data_end_rva() - info.get_raw_data_start_rva() == 8, "TLS test 3", test_level_normal);
	PE_TEST(info.get_raw_data() == std::string("\0\0\0\0\x37\x02\0\0", 8), "TLS test 4", test_level_normal);

	if(check_callbacks)
	{
		PE_TEST(info.get_tls_callbacks().empty(), "TLS test 5", test_level_normal);
	}

	if(image.get_pe_type() == pe_type_32)
	{
		PE_TEST(info.get_index_rva() == 0x420738 - image.get_image_base_32(), "TLS test 6", test_level_normal);

		if(check_callbacks)
		{
			PE_TEST(info.get_callbacks_rva() == 0x418188 - image.get_image_base_32(), "TLS test 7", test_level_normal);
		}
	}
	else
	{
		PE_TEST(info.get_index_rva() == 0x14002647Cull - image.get_image_base_64(), "TLS test 6", test_level_normal);

		if(check_callbacks)
		{
			PE_TEST(info.get_callbacks_rva() == 0x14001B310ull - image.get_image_base_64(), "TLS test 7", test_level_normal);
		}
	}
}

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));
	
	tls_info info;
	PE_TEST_EXCEPTION(info = get_tls_info(image), "TLS Parser test 1", test_level_critical);
	test_tls(info, image);

	section s;
	s.get_raw_data().resize(1);
	s.set_name("newtls");
	section& new_tls_section = image.add_section(s);
	uint32_t old_tls_rva = image.get_directory_rva(pe_win::image_directory_entry_tls);
	PE_TEST_EXCEPTION(rebuild_tls(image, info, new_tls_section, 0, false, false, tls_data_expand_raw, true, true), "TLS Rebuilder test 1", test_level_critical);
	PE_TEST(old_tls_rva != image.get_directory_rva(pe_win::image_directory_entry_tls), "TLS directory test", test_level_normal);

	PE_TEST_EXCEPTION(info = get_tls_info(image), "TLS Parser test 2", test_level_critical);
	test_tls(info, image);
	
	new_tls_section.set_raw_data("111");
	PE_TEST_EXCEPTION(rebuild_tls(image, info, new_tls_section, 3, false, false, tls_data_expand_raw, true, true), "TLS Rebuilder test 2", test_level_critical);
	PE_TEST_EXCEPTION(info = get_tls_info(image), "TLS Parser test 3", test_level_critical);
	PE_TEST(new_tls_section.get_raw_data().substr(0, 3) == "111", "TLS Rebuilder offset test", test_level_normal);
	test_tls(info, image);
	
	PE_TEST_EXCEPTION(rebuild_tls(image, info, new_tls_section, 12, false, false, tls_data_expand_raw, true, true), "TLS Rebuilder test 3", test_level_critical);
	PE_TEST_EXCEPTION(info = get_tls_info(image), "TLS Parser test 4", test_level_critical);
	test_tls(info, image);
	
	image.set_section_virtual_size(new_tls_section, 0x2000);
	info.set_raw_data_start_rva(image.rva_from_section_offset(new_tls_section, 0x1000));
	info.recalc_raw_data_end_rva();
	PE_TEST_EXCEPTION(rebuild_tls(image, info, new_tls_section, 12, false, true, tls_data_expand_raw, true, true), "TLS Rebuilder test 4", test_level_critical);
	PE_TEST_EXCEPTION(info = get_tls_info(image), "TLS Parser test 5", test_level_critical);
	test_tls(info, image);
	
	info.add_tls_callback(0x111);
	info.add_tls_callback(0x222);
	info.add_tls_callback(0x333);
	info.add_tls_callback(0x444);
	info.add_tls_callback(0x555);
	info.set_callbacks_rva(image.rva_from_section_offset(new_tls_section, 0x1500));

	PE_TEST_EXCEPTION(rebuild_tls(image, info, new_tls_section, 12, true, true, tls_data_expand_raw, true, true), "TLS Rebuilder test 5", test_level_critical);
	PE_TEST_EXCEPTION(info = get_tls_info(image), "TLS Parser test 6", test_level_critical);
	test_tls(info, image, false);
	PE_TEST(info.get_tls_callbacks().size() == 5, "TLS test 7", test_level_normal);
	PE_TEST(info.get_tls_callbacks()[2] == 0x333, "TLS test 8", test_level_normal);

	PE_TEST_END

	return 0;
}
