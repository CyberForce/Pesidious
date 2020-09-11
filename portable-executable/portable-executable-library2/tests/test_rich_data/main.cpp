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
	
	rich_data_list data;
	PE_TEST_EXCEPTION(data = get_rich_data(image), "Rich Data test 1", test_level_critical);
	PE_TEST(data.size() == 8, "Rich Data test 2", test_level_normal);
	PE_TEST(data[0].get_number() == 158, "Rich Data test 3", test_level_normal);

	if(image.get_pe_type() == pe_type_32)
	{
		PE_TEST(data[1].get_times() == 47, "Rich Data test 4", test_level_normal);
	}
	else
	{
		PE_TEST(data[1].get_times() == 48, "Rich Data test 4", test_level_normal);
	}

	PE_TEST(data[2].get_version() == 40219, "Rich Data test 5", test_level_normal);

	PE_TEST_END

	return 0;
}
