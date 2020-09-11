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
	resource_bitmap_reader bmp_read(res);
	resource_bitmap_writer bmp_write(res);
	
	PE_TEST_EXPECT_EXCEPTION(bmp_read.get_bitmap_by_name(L"TEST"), pe_exception::resource_directory_entry_not_found, "Bitmap Reader test 1", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(bmp_read.get_bitmap_by_name(123, L"TEST"), pe_exception::resource_directory_entry_not_found, "Bitmap Reader test 2", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(bmp_read.get_bitmap_by_id(123), pe_exception::resource_directory_entry_not_found, "Bitmap Reader test 3", test_level_normal);

	std::string bitmap;
	PE_TEST_EXCEPTION(bitmap = bmp_read.get_bitmap_by_id(102), "Bitmap Reader test 4", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(bmp_read.get_bitmap_by_id(102, 1), pe_exception::resource_data_entry_not_found, "Bitmap Reader test 5", test_level_normal);
	PE_TEST_EXCEPTION(bmp_write.add_bitmap(bitmap, L"TEST", 1049, 1234, 5678), "Bitmap Writer test 1", test_level_normal);
	
	std::string bitmap2;
	PE_TEST_EXCEPTION(bitmap2 = bmp_read.get_bitmap_by_name(1049, L"TEST"), "Bitmap Reader test 6", test_level_critical);
	PE_TEST(bitmap == bitmap2, "Bitmap Reader test 7", test_level_normal);
	
	PE_TEST_EXCEPTION(bmp_write.add_bitmap(bitmap, 9000, 1049, 1234, 5678), "Bitmap Writer test 2", test_level_critical);
	PE_TEST_EXCEPTION(bitmap2 = bmp_read.get_bitmap_by_id(9000), "Bitmap Reader test 8", test_level_normal);
	PE_TEST(bitmap == bitmap2, "Bitmap Reader test 9", test_level_normal);
	
	PE_TEST_EXCEPTION(bitmap = bmp_read.get_bitmap_by_id(103), "Bitmap Reader test 10", test_level_normal);
	PE_TEST_EXCEPTION(bmp_write.add_bitmap(bitmap, 9000, 1049, 1234, 5678), "Bitmap Writer test 3 (bitmap replace test)", test_level_critical);
	PE_TEST_EXCEPTION(bitmap2 = bmp_read.get_bitmap_by_id(9000), "Bitmap Reader test 11", test_level_normal);
	PE_TEST(bitmap == bitmap2, "Bitmap Reader test 12", test_level_normal);
	
	PE_TEST_EXCEPTION(bmp_write.remove_bitmap(9000, 1049), "Bitmap Writer test 4", test_level_critical);
	PE_TEST_EXPECT_EXCEPTION(bmp_read.get_bitmap_by_id(9000), pe_exception::resource_directory_entry_not_found, "Bitmap Reader test 13", test_level_normal);

	PE_TEST_EXCEPTION(bmp_write.remove_bitmap(L"TEST", 1049), "Bitmap Writer test 5", test_level_critical);
	PE_TEST_EXPECT_EXCEPTION(bmp_read.get_bitmap_by_name(L"TEST"), pe_exception::resource_directory_entry_not_found, "Bitmap Reader test 14", test_level_normal);

	PE_TEST_END

	return 0;
}
