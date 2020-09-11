#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <pe_bliss_resources.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void test_resources(const resource_directory& root)
{
	PE_TEST(root.get_entry_list().size() == 8, "Resource test 1", test_level_critical);
	PE_TEST(root.get_characteristics() == 0 && root.get_timestamp() == 0, "Resource test 2", test_level_normal);
	PE_TEST(root.get_minor_version() == 0 && root.get_major_version() == 4, "Resource test 3", test_level_normal);
	PE_TEST(root.get_number_of_named_entries() == 0 && root.get_number_of_id_entries() == 8, "Resource test 4", test_level_normal);
	PE_TEST(!root.get_entry_list()[1].is_named() && root.get_entry_list()[1].get_id() == pe_resource_viewer::resource_bitmap, "Resource test 5", test_level_normal);
	PE_TEST(!root.get_entry_list()[1].includes_data(), "Resource test 6", test_level_critical);

	const resource_directory& bitmap_root = root.get_entry_list()[1].get_resource_directory();
	PE_TEST(bitmap_root.get_number_of_named_entries() == 0 && bitmap_root.get_number_of_id_entries() == 3, "Resource test 7", test_level_critical);
	PE_TEST(!bitmap_root.get_entry_list()[1].is_named() && bitmap_root.get_entry_list()[1].get_id() == 102, "Resource test 8", test_level_normal);
	PE_TEST(!bitmap_root.get_entry_list()[1].includes_data(), "Resource test 9", test_level_critical);
	
	const resource_directory& bitmap_102_root = bitmap_root.get_entry_list()[1].get_resource_directory();
	PE_TEST(bitmap_102_root.get_number_of_named_entries() == 0 && bitmap_102_root.get_number_of_id_entries() == 1, "Resource test 10", test_level_critical);
	PE_TEST(!bitmap_102_root.get_entry_list()[0].is_named() && bitmap_102_root.get_entry_list()[0].get_id() == 1049, "Resource test 11", test_level_normal);
	PE_TEST(bitmap_102_root.get_entry_list()[0].includes_data(), "Resource test 12", test_level_critical);
	
	const resource_data_entry& bitmap_data = bitmap_102_root.get_entry_list()[0].get_data_entry();
	PE_TEST(bitmap_data.get_codepage() == 0x4E4, "Resource test 13", test_level_normal);
	PE_TEST(bitmap_data.get_data().substr(0, 5) == std::string("\x28\0\0\0\x4f", 5) && bitmap_data.get_data().size() == 0x4EE8, "Resource test 14", test_level_normal);
}

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));
	
	resource_directory root;
	
	PE_TEST_EXCEPTION(root = get_resources(image), "Resource Directory Parser test 1", test_level_critical);
	test_resources(root);
	
	section s;
	s.get_raw_data().resize(1);
	s.set_name("newrsrc");
	section& new_resource_section = image.add_section(s);
	uint32_t old_resources_rva = image.get_directory_rva(pe_win::image_directory_entry_resource);
	PE_TEST_EXCEPTION(rebuild_resources(image, root, new_resource_section, 0, true, true), "Resource Rebuilder test 1", test_level_critical);
	PE_TEST_EXCEPTION(root = get_resources(image), "Resource Directory Parser test 2", test_level_critical);
	PE_TEST(old_resources_rva != image.get_directory_rva(pe_win::image_directory_entry_resource), "Relocation Directory test", test_level_normal);
	test_resources(root);
	
	new_resource_section.set_raw_data("111");
	PE_TEST_EXCEPTION(rebuild_resources(image, root, new_resource_section, 3, true, true), "Resource Rebuilder test 2", test_level_critical);
	PE_TEST(new_resource_section.get_raw_data().substr(0, 3) == "111", "Resource Rebuilder Offset test", test_level_normal);
	PE_TEST_EXCEPTION(root = get_resources(image), "Resource Directory Parser test 3", test_level_critical);
	test_resources(root);

	PE_TEST_EXCEPTION(rebuild_resources(image, root, new_resource_section, 12, true, true), "Resource Rebuilder test 3", test_level_critical);
	PE_TEST_EXCEPTION(root = get_resources(image), "Resource Directory Parser test 4", test_level_critical);
	test_resources(root);

	{
		resource_directory& cursor_root = root.get_entry_list()[0].get_resource_directory();
		resource_directory_entry named_entry;
		named_entry.set_name(L"test entry");
		named_entry.add_data_entry(resource_data_entry("alala", 123));
		cursor_root.add_resource_directory_entry(named_entry);
	}

	PE_TEST_EXCEPTION(rebuild_resources(image, root, new_resource_section, 12, true, true), "Resource Rebuilder test 4", test_level_critical);
	PE_TEST_EXCEPTION(root = get_resources(image), "Resource Directory Parser test 5", test_level_critical);
	test_resources(root);

	resource_directory& cursor_root = root.get_entry_list()[0].get_resource_directory();
	PE_TEST(cursor_root.entry_by_name(L"test entry").get_data_entry().get_data() == "alala", "Resource named entry test", test_level_normal);

	PE_TEST_END

	return 0;
}
