#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <pe_bliss_resources.h>
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
	
	resource_directory root(get_resources(image));
	
	pe_resource_manager res(root);
	resource_cursor_icon_reader ico_read(res);
	resource_cursor_icon_writer ico_write(res);
	
	std::string icon, icon2;

	//Named icon groups tests
	PE_TEST_EXCEPTION(icon = ico_read.get_single_icon_by_id(5), "Icon Reader test 1", test_level_normal);
	PE_TEST_EXCEPTION(ico_write.add_icon(icon, L"NEW_GROUP", 1033, resource_cursor_icon_writer::icon_place_free_ids, 1234, 5678), "Icon Writer test 1", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_icon_by_name(1033, L"NEW_GROUP"), "Icon Reader test 2", test_level_normal); //This group contains single icon
	PE_TEST(icon == icon2, "Icon Reader test 3", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_icon_by_id(1), "Icon Reader test 4", test_level_normal); //icon_place_free_ids - the first free id was 1

	PE_TEST_EXCEPTION(ico_write.remove_icon_group(L"NEW_GROUP", 1033), "Icon Writer test 2", test_level_critical);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_icon_by_name(1033, L"NEW_GROUP"), pe_exception::resource_directory_entry_not_found, "Icon Reader test 5", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_single_icon_by_id(1), pe_exception::resource_directory_entry_not_found, "Icon Reader test 6", test_level_normal);

	PE_TEST_EXCEPTION(icon = ico_read.get_icon_by_name(1049, L"MAIN_ICON"), "Icon Reader test 7", test_level_normal);
	
	PE_TEST_EXCEPTION(ico_write.add_icon(icon, L"NEW_GROUP", 1033, resource_cursor_icon_writer::icon_place_after_max_icon_id, 1234, 5678), "Icon Writer test 3", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_icon_by_name(1033, L"NEW_GROUP"), "Icon Reader test 8", test_level_normal); //This group contains single icon
	PE_TEST(icon == icon2, "Icon Reader test 9", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_icon_by_id(18), "Icon Reader test 10", test_level_normal); //icon_place_after_max_icon_id - the last free id was 17, and MAIN_ICON contains more than one icon
	PE_TEST_EXCEPTION(ico_read.get_single_icon_by_id(19), "Icon Reader test 11", test_level_normal);

	PE_TEST_EXCEPTION(ico_write.remove_icon_group(L"NEW_GROUP", 1033), "Icon Writer test 4", test_level_critical);


	//ID icon groups tests
	PE_TEST_EXCEPTION(icon = ico_read.get_single_icon_by_id(5), "Icon Reader test 12", test_level_normal);
	PE_TEST_EXCEPTION(ico_write.add_icon(icon, 777, 1033, resource_cursor_icon_writer::icon_place_free_ids, 1234, 5678), "Icon Writer test 5", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_icon_by_id_lang(1033, 777), "Icon Reader test 13", test_level_normal); //This group contains single icon
	PE_TEST(icon == icon2, "Icon Reader test 14", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_icon_by_id(1), "Icon Reader test 15", test_level_normal); //icon_place_free_ids - the first free id was 1

	PE_TEST_EXCEPTION(ico_write.remove_icon_group(777, 1033), "Icon Writer test 6", test_level_critical);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_icon_by_id_lang(1033, 777), pe_exception::resource_directory_entry_not_found, "Icon Reader test 16", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_single_icon_by_id(1), pe_exception::resource_directory_entry_not_found, "Icon Reader test 17", test_level_normal);

	PE_TEST_EXCEPTION(icon = ico_read.get_icon_by_name(1049, L"MAIN_ICON"), "Icon Reader test 18", test_level_normal);
	
	PE_TEST_EXCEPTION(ico_write.add_icon(icon, 777, 1033, resource_cursor_icon_writer::icon_place_after_max_icon_id, 1234, 5678), "Icon Writer test 7", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_icon_by_id_lang(1033, 777), "Icon Reader test 19", test_level_normal); //This group contains single icon
	PE_TEST(icon == icon2, "Icon Reader test 20", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_icon_by_id(18), "Icon Reader test 21", test_level_normal); //icon_place_after_max_icon_id - the last free id was 17, and MAIN_ICON contains more than one icon
	PE_TEST_EXCEPTION(ico_read.get_single_icon_by_id(19), "Icon Reader test 22", test_level_normal);

	PE_TEST_EXCEPTION(ico_write.remove_icon_group(777, 1033), "Icon Writer test 8", test_level_critical);


	//Named cursor groups tests
	PE_TEST_EXCEPTION(icon = ico_read.get_single_cursor_by_id(3), "Cursor Reader test 1", test_level_normal);
	PE_TEST_EXCEPTION(ico_write.add_cursor(icon, L"NEW_GROUP", 1033, resource_cursor_icon_writer::icon_place_free_ids, 1234, 5678), "Cursor Writer test 1", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_cursor_by_name(1033, L"NEW_GROUP"), "Cursor Reader test 2", test_level_normal); //This group contains single cursor
	PE_TEST(icon == icon2, "Cursor Reader test 3", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_cursor_by_id(4), "Cursor Reader test 4", test_level_normal); //icon_place_free_ids - the first free id was 4

	PE_TEST_EXCEPTION(ico_write.remove_cursor_group(L"NEW_GROUP", 1033), "Cursor Writer test 2", test_level_critical);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_cursor_by_name(1033, L"NEW_GROUP"), pe_exception::resource_directory_entry_not_found, "Cursor Reader test 5", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_single_cursor_by_id(4), pe_exception::resource_directory_entry_not_found, "Cursor Reader test 6", test_level_normal);

	PE_TEST_EXCEPTION(icon = ico_read.get_cursor_by_id_lang(1049, 105), "Cursor Reader test 7", test_level_normal);
	
	PE_TEST_EXCEPTION(ico_write.add_cursor(icon, L"NEW_GROUP", 1033, resource_cursor_icon_writer::icon_place_after_max_icon_id, 1234, 5678), "Cursor Writer test 3", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_cursor_by_name(1033, L"NEW_GROUP"), "Cursor Reader test 8", test_level_normal); //This group contains single cursor
	PE_TEST(icon == icon2, "Cursor Reader test 9", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_cursor_by_id(4), "Cursor Reader test 10", test_level_normal); //icon_place_after_max_icon_id - the last free id was 4, and cursor group "105" contains more than one cursor
	PE_TEST_EXCEPTION(ico_read.get_single_cursor_by_id(5), "Cursor Reader test 11", test_level_normal);

	PE_TEST_EXCEPTION(ico_write.remove_cursor_group(L"NEW_GROUP", 1033), "Cursor Writer test 4", test_level_critical);


	//ID cursor groups tests
	PE_TEST_EXCEPTION(icon = ico_read.get_single_cursor_by_id(3), "Cursor Reader test 12", test_level_normal);
	PE_TEST_EXCEPTION(ico_write.add_cursor(icon, 777, 1033, resource_cursor_icon_writer::icon_place_free_ids, 1234, 5678), "Cursor Writer test 5", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_cursor_by_id_lang(1033, 777), "Cursor Reader test 13", test_level_normal); //This group contains single cursor
	PE_TEST(icon == icon2, "Cursor Reader test 14", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_cursor_by_id(4), "Cursor Reader test 15", test_level_normal); //icon_place_free_ids - the first free id was 4

	PE_TEST_EXCEPTION(ico_write.remove_cursor_group(777, 1033), "Cursor Writer test 6", test_level_critical);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_cursor_by_id_lang(1033, 777), pe_exception::resource_directory_entry_not_found, "Cursor Reader test 16", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(ico_read.get_single_cursor_by_id(4), pe_exception::resource_directory_entry_not_found, "Cursor Reader test 17", test_level_normal);

	PE_TEST_EXCEPTION(icon = ico_read.get_cursor_by_id_lang(1049, 105), "Cursor Reader test 18", test_level_normal);
	
	PE_TEST_EXCEPTION(ico_write.add_cursor(icon, 777, 1033, resource_cursor_icon_writer::icon_place_after_max_icon_id, 1234, 5678), "Cursor Writer test 7", test_level_critical);
	PE_TEST_EXCEPTION(icon2 = ico_read.get_cursor_by_id_lang(1033, 777), "Cursor Reader test 19", test_level_normal); //This group contains single cursor
	PE_TEST(icon == icon2, "Cursor Reader test 20", test_level_normal);
	PE_TEST_EXCEPTION(ico_read.get_single_cursor_by_id(4), "Cursor Reader test 21", test_level_normal); //icon_place_after_max_icon_id - the last free id was 4, and cursor group "105" contains more than one cursor
	PE_TEST_EXCEPTION(ico_read.get_single_cursor_by_id(5), "Cursor Reader test 22", test_level_normal);

	PE_TEST_EXCEPTION(ico_write.remove_cursor_group(777, 1033), "Cursor Writer test 8", test_level_critical);

	PE_TEST_END

	return 0;
}
