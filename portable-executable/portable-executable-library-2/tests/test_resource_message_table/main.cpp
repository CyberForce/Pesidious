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
	resource_message_list_reader msg(res);

	resource_message_list messages;

	//Unicode tests
	PE_TEST_EXCEPTION(messages = msg.get_message_table_by_id_lang(1049, 1), "Message Table Parser test 1", test_level_critical);
	PE_TEST(messages.size() == 2, "Message Table Parser test 2", test_level_critical);
	PE_TEST(messages.find(0x01000000) != messages.end()
		&& messages.find(0xC1000001) != messages.end(), "Message Table Parser test 3", test_level_critical);
	PE_TEST(messages[0xC1000001].is_unicode(), "Message Table Parser test 4", test_level_normal);
	PE_TEST(messages[0xC1000001].get_unicode_string() == L"Ошибка!\r\n", "Message Table Parser test 5", test_level_normal);

	PE_TEST_EXCEPTION(messages = msg.get_message_table_by_id_lang(1033, 1), "Message Table Parser test 6", test_level_critical);
	PE_TEST(messages.size() == 2, "Message Table Parser test 7", test_level_critical);
	PE_TEST(messages.find(0x01000000) != messages.end()
		&& messages.find(0xC1000001) != messages.end(), "Message Table Parser test 8", test_level_critical);
	PE_TEST(messages[0xC1000001].is_unicode(), "Message Table Parser test 9", test_level_normal);
	PE_TEST(messages[0xC1000001].get_unicode_string() == L"Error!\r\n", "Message Table Parser test 10", test_level_normal);

	//ANSI Tests
	PE_TEST_EXCEPTION(messages = msg.get_message_table_by_id_lang(1049, 2), "Message Table Parser test 11", test_level_critical);
	PE_TEST(messages.size() == 2, "Message Table Parser test 12", test_level_critical);
	PE_TEST(messages.find(0x01000000) != messages.end()
		&& messages.find(0xC1000001) != messages.end(), "Message Table Parser test 13", test_level_critical);
	PE_TEST(!messages[0xC1000001].is_unicode(), "Message Table Parser test 14", test_level_normal);
	PE_TEST(messages[0xC1000001].get_ansi_string() == "\xCE\xF8\xE8\xE1\xEA\xE0!\r\n", "Message Table Parser test 15", test_level_normal); //"Ошибка!\r\n"

	PE_TEST_EXCEPTION(messages = msg.get_message_table_by_id_lang(1033, 2), "Message Table Parser test 16", test_level_critical);
	PE_TEST(messages.size() == 2, "Message Table Parser test 17", test_level_critical);
	PE_TEST(messages.find(0x01000000) != messages.end()
		&& messages.find(0xC1000001) != messages.end(), "Message Table Parser test 18", test_level_critical);
	PE_TEST(!messages[0xC1000001].is_unicode(), "Message Table Parser test 19", test_level_normal);
	PE_TEST(messages[0xC1000001].get_ansi_string() == "Error!\r\n", "Message Table Parser test 20", test_level_normal);

	PE_TEST_END

	return 0;
}
