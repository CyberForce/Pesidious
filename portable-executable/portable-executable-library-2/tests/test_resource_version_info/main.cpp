#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <pe_bliss_resources.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void test_version(const resource_version_info_reader& ver_reader, file_version_info& file_info, lang_string_values_map& strings, translation_values_map& translations)
{
	strings.clear();
	translations.clear();

	PE_TEST_EXCEPTION(file_info = ver_reader.get_version_info(strings, translations), "Version Info Parser test 1", test_level_critical);
	PE_TEST(strings.size() == 2 && translations.size() == 2, "Version Info Parser test 2", test_level_critical);
	PE_TEST(strings.find(L"040004b0") != strings.end() && strings.find(L"041904b0") != strings.end(), "Version Info Parser test 3", test_level_critical);
	PE_TEST(translations.find(0x0400) != translations.end() && translations.find(0x0419) != translations.end(), "Version Info Parser test 4", test_level_critical);
	PE_TEST(strings[L"040004b0"][L"FileDescription"] == L"PE Bliss Test PE File", "Version Info Parser test 5", test_level_normal);
	PE_TEST(strings[L"041904b0"][L"FileDescription"] == L"PE Bliss - Тестовый PE-файл", "Version Info Parser test 6", test_level_normal);
	PE_TEST((*translations.find(0x0400)).second == 0x4b0 && (*translations.find(0x0419)).second == 0x4b0, "Version Info Parser test 7", test_level_normal);
	PE_TEST(file_info.get_file_date_ls() == 0 && file_info.get_file_date_ms() == 0
		&& file_info.get_file_flags() == 0 && file_info.get_file_os() == file_version_info::file_os_nt_win32
		&& file_info.get_file_subtype() == 0 && file_info.get_file_type() == file_version_info::file_type_application
		&& file_info.get_file_version_ls() == 0x00020001 && file_info.get_file_version_ms() == 0x00040003
		&& file_info.get_product_version_ls() == 0x00070008 && file_info.get_product_version_ms() == 0x00050006
		&& file_info.get_file_version_string<char>() == "4.3.2.1"
		&& file_info.get_product_version_string<wchar_t>() == L"5.6.7.8", "File Version Info Parser test", test_level_normal);

	version_info_viewer ver_view(strings, translations);
	version_info_editor ver_edit(strings, translations);

	PE_TEST(version_info_viewer::translation_from_string(L"041904b0").first == 0x0419
		&& version_info_viewer::translation_from_string(L"041904b0").second == 0x04b0, "translation_from_string test", test_level_normal);

	PE_TEST(ver_view.get_company_name() == L"PE Bliss", "Version Info Viewer test 1", test_level_normal);
	PE_TEST(ver_view.get_company_name(L"040004b0") == L"PE Bliss", "Version Info Viewer test 2", test_level_normal);
	PE_TEST(ver_view.get_file_description() == L"PE Bliss - Тестовый PE-файл", "Version Info Viewer test 3", test_level_normal);
	PE_TEST(ver_view.get_file_description(L"040004b0") == L"PE Bliss Test PE File", "Version Info Viewer test 4", test_level_normal);
	PE_TEST(ver_view.get_file_version() == L"4.3.2.1", "Version Info Viewer test 5", test_level_normal);
	PE_TEST(ver_view.get_file_version(L"040004b0") == L"4.3.2.1", "Version Info Viewer test 6", test_level_normal);
	PE_TEST(ver_view.get_internal_name() == L"test.exe", "Version Info Viewer test 7", test_level_normal);
	PE_TEST(ver_view.get_internal_name(L"040004b0") == L"test.exe", "Version Info Viewer test 8", test_level_normal);
	PE_TEST(ver_view.get_legal_copyright() == L"(C) dx", "Version Info Viewer test 9", test_level_normal);
	PE_TEST(ver_view.get_legal_copyright(L"040004b0") == L"(C) dx", "Version Info Viewer test 10", test_level_normal);
	PE_TEST(ver_view.get_original_filename() == L"original.exe", "Version Info Viewer test 11", test_level_normal);
	PE_TEST(ver_view.get_original_filename(L"040004b0") == L"original.exe", "Version Info Viewer test 12", test_level_normal);
	PE_TEST(ver_view.get_product_name() == L"PE Bliss - Тесты", "Version Info Viewer test 13", test_level_normal);
	PE_TEST(ver_view.get_product_name(L"040004b0") == L"PE Bliss Test", "Version Info Viewer test 14", test_level_normal);
	PE_TEST(ver_view.get_product_version() == L"5.6.7.8", "Version Info Viewer test 15", test_level_normal);
	PE_TEST(ver_view.get_product_version(L"040004b0") == L"5.6.7.8", "Version Info Viewer test 16", test_level_normal);
	PE_TEST(ver_view.get_property(L"CompanyName", L"", false) == L"PE Bliss", "Version Info Viewer test 17", test_level_normal);
	PE_TEST(ver_view.get_property(L"CompanyName", L"040004b0", false) == L"PE Bliss", "Version Info Viewer test 18", test_level_normal);
	PE_TEST(ver_view.get_property(L"TestProperty", L"", false) == L"", "Version Info Viewer test 19", test_level_normal);
	PE_TEST(ver_view.get_property(L"TestProperty", L"040004b0", false) == L"", "Version Info Viewer test 20", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(ver_view.get_property(L"TestProperty", L"", true) == L"", pe_exception::version_info_string_does_not_exist, "Version Info Viewer test 21", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(ver_view.get_property(L"TestProperty", L"040004b0", true) == L"", pe_exception::version_info_string_does_not_exist, "Version Info Viewer test 22", test_level_normal);
	PE_TEST(ver_view.get_translation_list().size() == 2, "Version Info Viewer test 23", test_level_critical);
	PE_TEST(ver_view.get_translation_list().at(1) == L"041904b0", "Version Info Viewer test 24", test_level_critical);
}

int main(int argc, char* argv[])
{
	PE_TEST_START

	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));

	resource_directory root(get_resources(image));

	pe_resource_manager res(root);
	resource_version_info_reader ver_reader(res);
	resource_version_info_writer ver_writer(res);

	file_version_info file_info;
	lang_string_values_map strings;
	translation_values_map translations;
	test_version(ver_reader, file_info, strings, translations);

	PE_TEST(ver_writer.remove_version_info(1049) == true, "Version Info Writer test 1", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(ver_reader.get_version_info(strings, translations), pe_exception::resource_directory_entry_not_found, "Version Info Parser test", test_level_critical);

	PE_TEST_EXCEPTION(ver_writer.set_version_info(file_info, strings, translations, 12345, 678, 123), "Version Info Writer test 2", test_level_critical);
	test_version(ver_reader, file_info, strings, translations);
	
	
	
	
	PE_TEST_END

	return 0;
}
