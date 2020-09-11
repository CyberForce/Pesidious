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
	
	uint32_t checksum = -1;
	PE_TEST_EXCEPTION(checksum = calculate_checksum(*pe_file), "Checksum test 1", test_level_normal);
	PE_TEST(image.get_checksum() == checksum, "Checksum test 2", test_level_normal);

	PE_TEST_END

	return 0;
}
