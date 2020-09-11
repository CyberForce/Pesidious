#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#define PE_FILES_UNUSED
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

int main(int argc, char* argv[])
{
	PE_TEST_START

	const char data[] = "abcdefgh";
	PE_TEST(pe_utils::is_null_terminated(data, sizeof(data)), "is_null_terminated test 1", test_level_normal);
	PE_TEST(!pe_utils::is_null_terminated(data, sizeof(data) - 1), "is_null_terminated test 2", test_level_normal);

	std::string str("test\0\0\0");
	PE_TEST_EXCEPTION(pe_utils::strip_nullbytes(str), "strip_nullbytes test 1", test_level_normal);
	PE_TEST(str == "test", "strip_nullbytes test 2", test_level_normal);

	PE_TEST(pe_utils::is_power_of_2(8), "is_power_of_2 test 1", test_level_normal);
	PE_TEST(!pe_utils::is_power_of_2(7), "is_power_of_2 test 2", test_level_normal);

	PE_TEST(pe_utils::align_down(99, 4) == 96, "align_down test 1", test_level_normal);
	PE_TEST(pe_utils::align_down(100, 4) == 100, "align_down test 2", test_level_normal);

	PE_TEST(pe_utils::align_up(99, 4) == 100, "align_up test 1", test_level_normal);
	PE_TEST(pe_utils::align_up(100, 4) == 100, "align_up test 2", test_level_normal);

	PE_TEST(pe_utils::is_sum_safe(100, 100), "is_sum_safe test 1", test_level_normal);
	PE_TEST(!pe_utils::is_sum_safe(pe_utils::max_dword - 1, 2), "is_sum_safe test 2", test_level_normal);

	std::ifstream file(argv[0]);
	file.seekg(0, std::ios::end);
	std::streamoff size = file.tellg();
	file.seekg(123);

	PE_TEST(pe_utils::get_file_size(file) == size, "get_file_size test 1", test_level_normal);
	PE_TEST(static_cast<std::streamoff>(file.tellg()) == static_cast<std::streamoff>(123), "get_file_size test 2", test_level_normal); //Restore position test

#ifndef PE_BLISS_WINDOWS
	PE_TEST(pe_utils::from_ucs2(pe_utils::to_ucs2(L"alala")) == L"alala", "to_ucs2 & from_ucs2 test 1", test_level_normal);
	PE_TEST(pe_utils::from_ucs2(pe_utils::to_ucs2(L"")) == L"", "to_ucs2 & from_ucs2 test 2", test_level_normal);
#endif

	PE_TEST_END

	return 0;
}
