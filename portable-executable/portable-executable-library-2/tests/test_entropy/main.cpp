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
	
	PE_TEST(entropy_calculator::calculate_entropy(image) > 3.0, "Entropy test 1", test_level_normal);
	PE_TEST(entropy_calculator::calculate_entropy(*pe_file) > 3.0, "Entropy test 2", test_level_normal);
	PE_TEST(entropy_calculator::calculate_entropy(image.get_image_sections().at(0)) > 3.0, "Entropy test 3", test_level_normal);

	const char data[] = "123456789";
	PE_TEST(entropy_calculator::calculate_entropy(data, sizeof(data) - 1) > 3.0, "Entropy test 4", test_level_normal);

	PE_TEST_EXPECT_EXCEPTION(entropy_calculator::calculate_entropy("", 0), pe_exception::data_is_empty, "Entropy test 5", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(entropy_calculator::calculate_entropy(section()), pe_exception::section_is_empty, "Entropy test 6", test_level_normal);

	PE_TEST_END

	return 0;
}
