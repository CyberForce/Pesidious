#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void test_exports(const export_info& info, const exported_functions_list& exports, const pe_base& image, bool test_rvas = true)
{
	PE_TEST(info.get_characteristics() == 0
		&& info.get_major_version() == 0
		&& info.get_minor_version() == 0
		&& info.get_ordinal_base() == 5
		&& info.get_name() == "test_dll.dll"
		&& info.get_number_of_functions() == 6
		&& info.get_number_of_names() == 3, "Exports test 1", test_level_normal);

	if(test_rvas)
	{
		if(image.get_pe_type() == pe_type_32)
		{
			PE_TEST(info.get_timestamp() == 0x509103D8
				&& info.get_rva_of_functions() == 0x00002588
				&& info.get_rva_of_names() == 0x000025A0
				&& info.get_rva_of_name_ordinals() == 0x000025AC, "Exports test 2", test_level_normal);
		}
		else
		{
			PE_TEST(info.get_timestamp() == 0x509103D3
				&& info.get_rva_of_functions() == 0x00002718
				&& info.get_rva_of_names() == 0x00002730
				&& info.get_rva_of_name_ordinals() == 0x0000273C, "Exports test 2", test_level_normal);
		}
	}

	PE_TEST(exports.size() == 4, "Exports test 3", test_level_critical);

	PE_TEST(exports[0].has_name() && exports[0].get_name() == "dll_func1", "Exports test 4", test_level_normal);
	PE_TEST(!exports[0].is_forwarded(), "Exports test 5", test_level_normal);
	PE_TEST(exports[0].get_name_ordinal() == 0 && exports[0].get_ordinal() == 5, "Exports test 6", test_level_normal);
	PE_TEST(exports[0].get_rva() == 0x00001000, "Exports test 7", test_level_normal);

	PE_TEST(exports[2].has_name() && exports[2].get_name() == "MsgBoxA", "Exports test 8", test_level_normal);
	PE_TEST(exports[2].is_forwarded() && exports[2].get_forwarded_name() == "USER32.MessageBoxA", "Exports test 9", test_level_normal);
	PE_TEST(exports[2].get_name_ordinal() == 2 && exports[2].get_ordinal() == 7, "Exports test 10", test_level_normal);

	if(test_rvas)
	{
		if(image.get_pe_type() == pe_type_32)
		{
			PE_TEST(exports[2].get_rva() == 0x000025DB, "Exports test 11", test_level_normal);
		}
		else
		{
			PE_TEST(exports[2].get_rva() == 0x0000276B, "Exports test 11", test_level_normal);
		}
	}

	PE_TEST(!exports[3].has_name() && exports[3].get_ordinal() == 0xA, "Exports test 12", test_level_normal);
	PE_TEST(!exports[3].is_forwarded(), "Exports test 13", test_level_normal);
	PE_TEST(exports[3].get_rva() == 0x00001020, "Exports test 14", test_level_normal);

	std::pair<uint16_t, uint16_t> limits;
	PE_TEST_EXCEPTION(limits = get_export_ordinal_limits(exports), "get_export_ordinal_limits test 1", test_level_normal);
	PE_TEST(limits.first == info.get_ordinal_base() && limits.second == 0xA, "get_export_ordinal_limits test 2", test_level_normal);

	PE_TEST(exported_name_exists("MsgBoxA", exports), "exported_name_exists test 1", test_level_normal);
	PE_TEST(exported_name_exists("dll_func1", exports), "exported_name_exists test 2", test_level_normal);
	PE_TEST(!exported_name_exists("dll_func2", exports), "exported_name_exists test 3", test_level_normal);
	PE_TEST(!exported_name_exists("USER32.MessageBoxA", exports), "exported_name_exists test 4", test_level_normal);

	PE_TEST(exported_ordinal_exists(0x5, exports), "exported_ordinal_exists test 1", test_level_normal);
	PE_TEST(exported_ordinal_exists(0xA, exports), "exported_ordinal_exists test 2", test_level_normal);
	PE_TEST(!exported_ordinal_exists(0x1, exports), "exported_ordinal_exists test 3", test_level_normal);
	PE_TEST(!exported_ordinal_exists(0x9, exports), "exported_ordinal_exists test 4", test_level_normal);
}

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));

	exported_functions_list exports;
	export_info info;
	PE_TEST_EXCEPTION(exports = get_exported_functions(image, info), "Exports Parser test 1", test_level_critical);
	test_exports(info, exports, image);

	PE_TEST_EXCEPTION(rebuild_exports(image, info, exports, image.section_from_directory(pe_win::image_directory_entry_export), 0, true, true), "Exports Rebuilder test 1", test_level_critical);
	PE_TEST_EXCEPTION(exports = get_exported_functions(image, info), "Exports Parser test 2", test_level_critical);
	test_exports(info, exports, image, false);
	
	section s;
	s.get_raw_data().resize(1);
	s.set_name("newexp");
	section& new_export_section = image.add_section(s);
	uint32_t old_export_rva = image.get_directory_rva(pe_win::image_directory_entry_export);
	PE_TEST_EXCEPTION(rebuild_exports(image, info, exports, new_export_section, 0, true, true), "Exports Rebuilder test 2", test_level_critical);
	PE_TEST(old_export_rva != image.get_directory_rva(pe_win::image_directory_entry_export), "Exports Rebuilder test 3", test_level_normal);
	PE_TEST_EXCEPTION(exports = get_exported_functions(image, info), "Exports Parser test 3", test_level_critical);
	test_exports(info, exports, image, false);
	
	new_export_section.set_raw_data("111");
	PE_TEST_EXCEPTION(rebuild_exports(image, info, exports, new_export_section, 3, true, true), "Exports Rebuilder test 4", test_level_critical);
	PE_TEST(new_export_section.get_raw_data().substr(0, 3) == "111", "Exports Rebuilder offset test 1", test_level_normal);
	PE_TEST_EXCEPTION(exports = get_exported_functions(image, info), "Exports Parser test 4", test_level_critical);
	test_exports(info, exports, image, false);
	
	new_export_section.set_raw_data("111111111111");
	PE_TEST_EXCEPTION(rebuild_exports(image, info, exports, new_export_section, 12, true, true), "Exports Rebuilder test 5", test_level_critical);
	PE_TEST(new_export_section.get_raw_data().substr(0, 12) == "111111111111", "Exports Rebuilder offset test 2", test_level_normal);
	PE_TEST_EXCEPTION(exports = get_exported_functions(image, info), "Exports Parser test 5", test_level_critical);
	test_exports(info, exports, image, false);

	exported_function func;
	func.set_ordinal(0xA);
	func.set_name("DuplicatedOrdinal");
	func.set_rva(0x1000);
	exports.push_back(func);
	PE_TEST_EXPECT_EXCEPTION(rebuild_exports(image, info, exports, new_export_section, 12, true, true), pe_exception::duplicate_exported_function_ordinal, "Exports Rebuilder test 6", test_level_normal);

	exports.back().set_ordinal(0xC);
	exports.back().set_name("MsgBoxA"); //Duplicate name
	PE_TEST_EXPECT_EXCEPTION(rebuild_exports(image, info, exports, new_export_section, 12, true, true), pe_exception::duplicate_exported_function_name, "Exports Rebuilder test 7", test_level_normal);
	
	exports.back().set_ordinal(0xC);
	exports.back().set_name("ANewFunction");
	exports.back().set_ordinal(0xF);
	PE_TEST_EXCEPTION(rebuild_exports(image, info, exports, new_export_section, 12, true, true), "Exports Rebuilder test 8", test_level_normal);
	PE_TEST_EXCEPTION(exports = get_exported_functions(image, info), "Exports Parser test 6", test_level_critical);

	PE_TEST(exports.size() == 5, "New Exported Function test 1", test_level_critical);
	PE_TEST(exports[4].has_name() && exports[4].get_name() == "ANewFunction", "New Exported Function test 2", test_level_normal);
	PE_TEST(!exports[4].is_forwarded(), "New Exported Function test 3", test_level_normal);
	PE_TEST(exports[4].get_rva() == 0x00001000, "New Exported Function test 4", test_level_normal);

	PE_TEST_END

	return 0;
}
